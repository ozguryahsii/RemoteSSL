using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Deployments;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>Tenant isolation — design doc §35, ADR-008.</summary>
public class TenancyTests
{
    private static readonly Guid TenantA = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TenantB = new("bbbbbbbb-0000-0000-0000-000000000002");

    /// <summary>
    /// One database, two tenants. The context is constructed per call with the same store name, so
    /// these behave like two connections to the same database rather than two databases.
    /// </summary>
    private static RemoteSslDbContext Db(string store, ITenantContext tenants) =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>().UseInMemoryDatabase(store).Options, tenants);

    private static TenantContext At(Guid tenantId)
    {
        var context = new TenantContext();
        context.Enter(tenantId);
        return context;
    }

    private static async Task SeedAsync(string store)
    {
        using var a = Db(store, At(TenantA));
        a.Certificates.Add(new Certificate { Id = Guid.NewGuid(), CommonName = "a.example.com" });
        a.MonitorEndpoints.Add(new MonitorEndpoint { Id = Guid.NewGuid(), Host = "a.example.com", Port = 443 });
        await a.SaveChangesAsync();

        using var b = Db(store, At(TenantB));
        b.Certificates.Add(new Certificate { Id = Guid.NewGuid(), CommonName = "b.example.com" });
        await b.SaveChangesAsync();
    }

    [Fact]
    public async Task A_tenant_sees_only_its_own_rows()
    {
        var store = $"tenancy-{Guid.NewGuid()}";
        await SeedAsync(store);

        using var a = Db(store, At(TenantA));
        using var b = Db(store, At(TenantB));

        Assert.Equal("a.example.com", (await a.Certificates.SingleAsync()).CommonName);
        Assert.Equal("b.example.com", (await b.Certificates.SingleAsync()).CommonName);
    }

    [Fact]
    public async Task A_row_created_inside_a_tenant_is_stamped_with_it()
    {
        var store = $"tenancy-{Guid.NewGuid()}";
        using var a = Db(store, At(TenantA));
        a.Targets.Add(new Target { Id = Guid.NewGuid(), Name = "web01", AdapterType = "nginx" });
        await a.SaveChangesAsync();

        // Read back without a filter to see what was actually written.
        var context = new TenantContext();
        using var _ = context.EnterCrossTenant();
        using var all = Db(store, context);
        Assert.Equal(TenantA, (await all.Targets.SingleAsync()).TenantId);
    }

    [Fact]
    public async Task Another_tenants_row_cannot_be_reached_even_by_its_id()
    {
        var store = $"tenancy-{Guid.NewGuid()}";
        await SeedAsync(store);

        Guid idOfB;
        var cross = new TenantContext();
        using (var _ = cross.EnterCrossTenant())
        using (var all = Db(store, cross))
            idOfB = (await all.Certificates.FirstAsync(c => c.CommonName == "b.example.com")).Id;

        using var a = Db(store, At(TenantA));
        Assert.Null(await a.Certificates.FirstOrDefaultAsync(c => c.Id == idOfB));
    }

    [Fact]
    public async Task Cross_tenant_mode_sees_everything_which_is_what_a_scheduler_needs()
    {
        var store = $"tenancy-{Guid.NewGuid()}";
        await SeedAsync(store);

        var context = new TenantContext();
        using var _ = context.EnterCrossTenant();
        using var all = Db(store, context);

        Assert.Equal(2, await all.Certificates.CountAsync());
    }

    [Fact]
    public void Leaving_cross_tenant_mode_restores_the_previous_tenant()
    {
        var context = At(TenantA);
        using (var _ = context.EnterCrossTenant())
        {
            Assert.True(context.CrossTenant);
            Assert.Null(context.TenantId);
        }

        // A background pass must not leak its unfiltered view into whatever runs next.
        Assert.False(context.CrossTenant);
        Assert.Equal(TenantA, context.TenantId);
    }

    [Fact]
    public async Task Child_rows_are_filtered_too_so_a_query_cannot_start_below_the_boundary()
    {
        var store = $"tenancy-{Guid.NewGuid()}";
        using (var a = Db(store, At(TenantA)))
        {
            a.CertificateStores.Add(new CertificateStore
            {
                Id = Guid.NewGuid(), TargetId = Guid.NewGuid(), StoreType = "pem-file", StorePath = "/etc/ssl/a.crt"
            });
            await a.SaveChangesAsync();
        }

        using var b = Db(store, At(TenantB));
        Assert.Empty(await b.CertificateStores.ToListAsync());
    }

    [Fact]
    public async Task Background_work_with_no_tenant_still_lands_in_the_default_tenant()
    {
        var store = $"tenancy-{Guid.NewGuid()}";
        var context = new TenantContext();
        using (var _ = context.EnterCrossTenant())
        using (var db = Db(store, context))
        {
            db.Certificates.Add(new Certificate { Id = Guid.NewGuid(), CommonName = "scheduler.example.com" });
            await db.SaveChangesAsync();
        }

        using var defaultTenant = Db(store, At(Tenant.DefaultTenantId));
        Assert.Equal("scheduler.example.com", (await defaultTenant.Certificates.SingleAsync()).CommonName);
    }
}

/// <summary>Runner failover and affinity — design doc §8.2, §34.2.</summary>
public class RunnerFailoverTests
{
    private sealed class NullSink : INotificationSink
    {
        public void Notify(string eventType, object payload) { }
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"failover-{Guid.NewGuid()}").Options);

    private static RunnerFailover Failover(RemoteSslDbContext db) =>
        new(db, new AuditWriter(db), new NullSink());

    private static RunnerNode Runner(string name, RunnerStatus status, string? group = "dc1") => new()
    {
        Id = Guid.NewGuid(), Name = name, Status = status, AffinityGroup = group,
        RegisteredAt = DateTimeOffset.UtcNow
    };

    private static RunnerJob Job(Guid runnerId, DateTimeOffset leaseExpiry, string? group = "dc1",
        string status = "Claimed", bool nonReassignable = false, int attempts = 1) => new()
    {
        Id = Guid.NewGuid(), RunnerId = runnerId, JobType = "deploy", Status = status,
        AffinityGroup = group, LeaseExpiresAt = leaseExpiry, Attempts = attempts,
        NonReassignable = nonReassignable, ClaimedAt = DateTimeOffset.UtcNow.AddMinutes(-10),
        CorrelationId = Guid.NewGuid().ToString("N"), CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-15)
    };

    [Fact]
    public async Task A_job_stranded_on_an_offline_runner_goes_back_to_the_queue()
    {
        using var db = CreateDb();
        var runner = Runner("r1", RunnerStatus.Offline);
        db.Runners.Add(runner);
        var job = Job(runner.Id, DateTimeOffset.UtcNow.AddMinutes(-1));
        db.RunnerJobs.Add(job);
        await db.SaveChangesAsync();

        var result = await Failover(db).ReclaimAsync(DateTimeOffset.UtcNow, 3, default);

        Assert.Equal(1, result.Requeued);
        var reclaimed = await db.RunnerJobs.SingleAsync();
        Assert.Equal("Queued", reclaimed.Status);
        Assert.Null(reclaimed.RunnerId);
        Assert.Equal(runner.Id, reclaimed.ReassignedFromRunnerId);
        Assert.Null(reclaimed.LeaseExpiresAt);
    }

    [Fact]
    public async Task A_job_on_a_runner_that_is_still_online_is_left_alone_and_its_lease_extended()
    {
        using var db = CreateDb();
        var runner = Runner("r1", RunnerStatus.Online);
        db.Runners.Add(runner);
        db.RunnerJobs.Add(Job(runner.Id, DateTimeOffset.UtcNow.AddMinutes(-1)));
        await db.SaveChangesAsync();

        var now = DateTimeOffset.UtcNow;
        var result = await Failover(db).ReclaimAsync(now, 3, default);

        Assert.Equal(0, result.Requeued);
        var job = await db.RunnerJobs.SingleAsync();
        Assert.Equal("Claimed", job.Status);
        Assert.True(job.LeaseExpiresAt > now);
    }

    [Fact]
    public async Task A_job_that_already_touched_its_target_is_failed_rather_than_repeated_elsewhere()
    {
        using var db = CreateDb();
        var runner = Runner("r1", RunnerStatus.Offline);
        db.Runners.Add(runner);
        db.RunnerJobs.Add(Job(runner.Id, DateTimeOffset.UtcNow.AddMinutes(-1),
            status: "Running", nonReassignable: true));
        await db.SaveChangesAsync();

        var result = await Failover(db).ReclaimAsync(DateTimeOffset.UtcNow, 3, default);

        Assert.Equal(1, result.Failed);
        var job = await db.RunnerJobs.SingleAsync();
        Assert.Equal("Failed", job.Status);
        Assert.Contains("apply the change twice", job.ResultJson);
        Assert.True(await db.AuditEvents.AnyAsync(e => e.Action == "runner.job-abandoned"));
    }

    [Fact]
    public async Task A_job_no_runner_could_finish_is_given_up_on_after_the_attempt_budget()
    {
        using var db = CreateDb();
        var runner = Runner("r1", RunnerStatus.Offline);
        db.Runners.Add(runner);
        db.RunnerJobs.Add(Job(runner.Id, DateTimeOffset.UtcNow.AddMinutes(-1), attempts: 3));
        await db.SaveChangesAsync();

        var result = await Failover(db).ReclaimAsync(DateTimeOffset.UtcNow, 3, default);

        Assert.Equal(1, result.Failed);
        Assert.Contains("after 3 attempt", (await db.RunnerJobs.SingleAsync()).ResultJson);
    }

    [Fact]
    public async Task A_job_whose_lease_has_not_expired_is_not_touched()
    {
        using var db = CreateDb();
        var runner = Runner("r1", RunnerStatus.Offline);
        db.Runners.Add(runner);
        db.RunnerJobs.Add(Job(runner.Id, DateTimeOffset.UtcNow.AddMinutes(5)));
        await db.SaveChangesAsync();

        var result = await Failover(db).ReclaimAsync(DateTimeOffset.UtcNow, 3, default);

        Assert.Equal(0, result.Requeued);
        Assert.Equal(0, result.Failed);
    }

    [Fact]
    public void A_runner_outside_the_jobs_affinity_group_may_not_take_it()
    {
        var job = new RunnerJob { Id = Guid.NewGuid(), AffinityGroup = "dc1" };

        Assert.True(RunnerFailover.CanRun(Runner("in", RunnerStatus.Online, "dc1"), job));
        Assert.False(RunnerFailover.CanRun(Runner("out", RunnerStatus.Online, "dc2"), job));
        Assert.False(RunnerFailover.CanRun(Runner("none", RunnerStatus.Online, null), job));
    }

    [Fact]
    public void A_job_with_no_affinity_group_may_be_taken_by_any_runner()
    {
        var job = new RunnerJob { Id = Guid.NewGuid(), AffinityGroup = null };

        Assert.True(RunnerFailover.CanRun(Runner("anywhere", RunnerStatus.Online, "dc9"), job));
    }

    [Fact]
    public void A_pinned_job_stays_with_its_runner()
    {
        var mine = Runner("mine", RunnerStatus.Online);
        var other = Runner("other", RunnerStatus.Online);
        var job = new RunnerJob { Id = Guid.NewGuid(), RunnerId = mine.Id };

        Assert.True(RunnerFailover.CanRun(mine, job));
        Assert.False(RunnerFailover.CanRun(other, job));
    }

    [Fact]
    public void A_runner_whose_identity_was_revoked_may_not_take_work()
    {
        var revoked = Runner("revoked", RunnerStatus.Online);
        revoked.IdentityRevokedAt = DateTimeOffset.UtcNow;

        Assert.False(RunnerFailover.CanRun(revoked, new RunnerJob { Id = Guid.NewGuid() }));
    }

    [Fact]
    public void The_reassignment_rule_explains_itself_rather_than_returning_a_bare_no()
    {
        var touched = new RunnerJob { Id = Guid.NewGuid(), NonReassignable = true };
        var exhausted = new RunnerJob { Id = Guid.NewGuid(), Attempts = 5 };
        var fine = new RunnerJob { Id = Guid.NewGuid(), Attempts = 1 };

        Assert.Contains("twice", RunnerFailover.ReassignmentBlocker(touched, 3));
        Assert.Contains("attempt", RunnerFailover.ReassignmentBlocker(exhausted, 3));
        Assert.Null(RunnerFailover.ReassignmentBlocker(fine, 3));
    }
}
