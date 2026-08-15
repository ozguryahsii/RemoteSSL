using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Automation;
using RemoteSSL.Application.Events;
using RemoteSSL.Application.Security;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>
/// The scheduled expiry scan of design doc §29.1, which FR-002 depends on.
///
/// Expiry alerting used to happen only where a probe observed a certificate, so a certificate
/// with no monitor endpoint — issued here and deployed to an internal target nobody probes, or
/// simply imported — never raised a single T-90…T-1 alarm. These tests hold that door shut.
/// </summary>
public class ExpiryScanTests
{
    private sealed class RecordingSink : INotificationSink
    {
        public List<(string Event, object Payload)> Sent { get; } = [];
        public void Notify(string eventType, object payload) => Sent.Add((eventType, payload));
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"expiry-{Guid.NewGuid()}").Options);

    /// <summary>A certificate with an active version expiring in <paramref name="daysLeft"/> days.</summary>
    private static async Task<Certificate> SeedAsync(RemoteSslDbContext db, int daysLeft)
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = new Certificate
        {
            Id = Guid.NewGuid(), CommonName = "unwatched.example.com", Environment = "PROD",
            HealthStatus = CertificateHealthStatus.Healthy, CreatedAt = now, UpdatedAt = now
        };
        db.Certificates.Add(certificate);
        db.CertificateVersions.Add(new CertificateVersion
        {
            Id = Guid.NewGuid(), CertificateId = certificate.Id, Certificate = certificate,
            Status = CertificateVersionStatus.Active,
            Sha256Thumbprint = new string('B', 64),
            // +12 hours so the flooring in DaysUntilExpiry lands on exactly daysLeft.
            NotBefore = now.AddDays(-1), NotAfter = now.AddDays(daysLeft).AddHours(12)
        });
        await db.SaveChangesAsync();
        return certificate;
    }

    private static AutomationService Service(RemoteSslDbContext db, RecordingSink sink) =>
        new(db, null!, null!, new AuditWriter(db), sink, NullLogger<AutomationService>.Instance);

    /// <summary>Runs only the parts of the tick that do not need the request/deployment services.</summary>
    private static Task ScanAsync(RemoteSslDbContext db, RecordingSink sink) =>
        Service(db, sink).ExpiryScanForTestsAsync(default);

    [Fact]
    public async Task A_certificate_nobody_probes_still_raises_its_expiry_alarm()
    {
        await using var db = CreateDb();
        var certificate = await SeedAsync(db, daysLeft: 29);
        var sink = new RecordingSink();

        await ScanAsync(db, sink);

        // No monitor endpoint exists at all — the alarm has to come from the inventory.
        Assert.Empty(await db.MonitorEndpoints.ToListAsync());
        Assert.Contains(sink.Sent, s => s.Event == DomainEvents.CertificateExpiring);

        var stored = await db.Certificates.FirstAsync(c => c.Id == certificate.Id);
        Assert.Equal(CertificateHealthStatus.ExpiringSoon, stored.HealthStatus);
    }

    [Fact]
    public async Task Each_threshold_alerts_once_no_matter_how_often_the_scan_runs()
    {
        await using var db = CreateDb();
        await SeedAsync(db, daysLeft: 29);
        var sink = new RecordingSink();

        // The tick runs continuously; an alarm per tick would be noise, not a signal.
        await ScanAsync(db, sink);
        await ScanAsync(db, sink);
        await ScanAsync(db, sink);

        Assert.Single(sink.Sent.Where(s => s.Event == DomainEvents.CertificateExpiring));
    }

    [Fact]
    public async Task First_sight_of_a_long_overdue_certificate_raises_one_alarm_not_four()
    {
        await using var db = CreateDb();
        await SeedAsync(db, daysLeft: 29);       // already past T-90, T-60, T-45 and T-30
        var sink = new RecordingSink();

        await ScanAsync(db, sink);

        // Announcing the earlier thresholds now would claim they just happened, and on the first
        // tick across a real inventory it would be an alarm storm rather than a signal.
        var alert = Assert.Single(sink.Sent.Where(s => s.Event == DomainEvents.CertificateExpiring));
        Assert.Contains("threshold = 30", alert.Payload.ToString());
    }

    [Fact]
    public async Task Crossing_further_thresholds_alerts_again()
    {
        await using var db = CreateDb();
        var certificate = await SeedAsync(db, daysLeft: 29);
        var sink = new RecordingSink();

        await ScanAsync(db, sink);   // crosses T-30

        // Time passes; the same certificate is now inside T-15 and T-7.
        var version = await db.CertificateVersions.FirstAsync();
        version.NotAfter = DateTimeOffset.UtcNow.AddDays(6).AddHours(12);
        await db.SaveChangesAsync();

        await ScanAsync(db, sink);

        var alerts = sink.Sent.Where(s => s.Event == DomainEvents.CertificateExpiring).ToList();
        Assert.Equal(3, alerts.Count);   // T-30, then T-15 and T-7

        var stored = await db.Certificates.FirstAsync(c => c.Id == certificate.Id);
        Assert.Equal(CertificateHealthStatus.Critical, stored.HealthStatus);
    }

    [Fact]
    public async Task A_renewal_that_pushes_the_expiry_out_lets_the_new_version_alert_on_its_own()
    {
        await using var db = CreateDb();
        await SeedAsync(db, daysLeft: 5);
        var sink = new RecordingSink();

        await ScanAsync(db, sink);
        var beforeRenewal = sink.Sent.Count(s => s.Event == DomainEvents.CertificateExpiring);
        Assert.True(beforeRenewal > 0);

        // Renewed: a year of life. Without clearing the alert history the new version would stay
        // silent for ever, because every threshold would look "already alerted".
        var version = await db.CertificateVersions.FirstAsync();
        version.NotAfter = DateTimeOffset.UtcNow.AddDays(365);
        await db.SaveChangesAsync();

        await ScanAsync(db, sink);       // nothing to say yet
        Assert.Equal(beforeRenewal, sink.Sent.Count(s => s.Event == DomainEvents.CertificateExpiring));

        version.NotAfter = DateTimeOffset.UtcNow.AddDays(29).AddHours(12);
        await db.SaveChangesAsync();
        await ScanAsync(db, sink);

        Assert.True(sink.Sent.Count(s => s.Event == DomainEvents.CertificateExpiring) > beforeRenewal);
    }

    [Fact]
    public async Task An_expired_certificate_says_so_and_a_revoked_one_stays_quiet()
    {
        await using var db = CreateDb();
        var certificate = await SeedAsync(db, daysLeft: -3);
        var sink = new RecordingSink();

        await ScanAsync(db, sink);
        Assert.Contains(sink.Sent, s => s.Event == DomainEvents.CertificateExpired);
        Assert.Equal(CertificateHealthStatus.Expired,
            (await db.Certificates.FirstAsync(c => c.Id == certificate.Id)).HealthStatus);

        // Revoking it ends the conversation: its expiry is no longer news.
        certificate.HealthStatus = CertificateHealthStatus.Revoked;
        await db.SaveChangesAsync();

        var second = new RecordingSink();
        await ScanAsync(db, second);
        Assert.Empty(second.Sent);
    }

    [Fact]
    public async Task Deployment_state_is_not_overwritten_by_the_expiry_scan()
    {
        await using var db = CreateDb();
        var certificate = await SeedAsync(db, daysLeft: 200);
        certificate.HealthStatus = CertificateHealthStatus.PendingDeployment;
        await db.SaveChangesAsync();

        await ScanAsync(db, new RecordingSink());

        // §19.2: deployment state outranks expiry-derived health; the scan must not reset it to
        // Healthy and hide a deployment that never landed.
        Assert.Equal(CertificateHealthStatus.PendingDeployment,
            (await db.Certificates.FirstAsync(c => c.Id == certificate.Id)).HealthStatus);
    }
}

/// <summary>
/// The two scope dimensions of §24.2 that authorization was missing: business unit and
/// certificate tag. Without them a rule naming either could never match, so a grant meant to
/// cover one division's estate silently covered nothing — or, read the other way, a deployment
/// crossed a boundary the document says it must not.
/// </summary>
public class ScopeDimensionTests
{
    [Fact]
    public void A_grant_for_one_business_unit_does_not_reach_another()
    {
        ScopeRule[] rules = [new("certificate.deploy", BusinessUnit: "retail")];

        Assert.True(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", BusinessUnit: "retail")));
        Assert.False(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", BusinessUnit: "treasury")));
    }

    [Fact]
    public void A_tag_scoped_grant_covers_the_tagged_certificates_and_only_those()
    {
        ScopeRule[] rules = [new("certificate.deploy", CertificateTag: "pci")];

        Assert.True(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", CertificateTags: ["public-web", "pci"])));
        Assert.False(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", CertificateTags: ["public-web"])));
    }

    [Fact]
    public void An_untagged_certificate_is_not_covered_by_a_tag_scoped_grant()
    {
        // The safe reading: a grant narrowed to a tag must not widen to everything untagged.
        ScopeRule[] rules = [new("certificate.deploy", CertificateTag: "pci")];

        Assert.False(ScopeEvaluator.IsAllowed(rules, new ScopeRequest("certificate.deploy")));
        Assert.False(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", CertificateTags: [])));
    }

    [Fact]
    public void All_five_dimensions_narrow_together_rather_than_independently()
    {
        // §24.2's example is one rule carrying several constraints; every one of them must hold.
        ScopeRule[] rules =
        [
            new("certificate.deploy", Environment: "PROD", TargetGroup: "WEB",
                Adapters: ["nginx", "iis"], BusinessUnit: "retail", CertificateTag: "pci")
        ];

        var allowed = new ScopeRequest("certificate.deploy", "PROD", "WEB", "nginx",
            BusinessUnit: "retail", CertificateTags: ["pci"]);
        Assert.True(ScopeEvaluator.IsAllowed(rules, allowed));

        Assert.False(ScopeEvaluator.IsAllowed(rules, allowed with { Environment = "DEV" }));
        Assert.False(ScopeEvaluator.IsAllowed(rules, allowed with { TargetGroup = "APP" }));
        Assert.False(ScopeEvaluator.IsAllowed(rules, allowed with { Adapter = "haproxy" }));
        Assert.False(ScopeEvaluator.IsAllowed(rules, allowed with { BusinessUnit = "treasury" }));
        Assert.False(ScopeEvaluator.IsAllowed(rules, allowed with { CertificateTags = ["public-web"] }));
    }

    [Fact]
    public void A_rule_that_names_no_unit_or_tag_still_matches_everything_it_used_to()
    {
        // Adding dimensions must not narrow grants that already existed.
        ScopeRule[] rules = [new("certificate.deploy", Environment: "PROD")];

        Assert.True(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", "PROD", BusinessUnit: "retail",
                CertificateTags: ["pci"])));
        Assert.True(ScopeEvaluator.IsAllowed(rules, new ScopeRequest("certificate.deploy", "PROD")));
    }
}
