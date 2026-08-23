using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>
/// The list the product opens on.
///
/// Its worth is entirely in what it leaves out: a list that repeats one problem five times, or
/// tells you to renew something already being renewed, is one people stop reading — and a work
/// list nobody reads is worse than none, because it looks like coverage.
/// </summary>
public class WorkListTests
{
    [Fact]
    public async Task A_certificate_near_its_end_is_something_to_do()
    {
        await using var db = CreateDb();
        Expiring(db, "www.example.com", days: 20);
        await db.SaveChangesAsync();

        var items = await new WorkListService(db).BuildAsync(default);

        var item = Assert.Single(items, i => i.Kind == "expiring");
        Assert.Equal("www.example.com", item.Title);
        Assert.Equal(20, item.DaysLeft);
        Assert.Equal("Renew it", item.Action);
    }

    [Fact]
    public async Task A_certificate_with_months_left_is_not()
    {
        await using var db = CreateDb();
        Expiring(db, "calm.example.com", days: 200);
        await db.SaveChangesAsync();

        Assert.Empty(await new WorkListService(db).BuildAsync(default));
    }

    [Fact]
    public async Task A_renewal_already_under_way_replaces_the_reminder_to_start_one()
    {
        // Otherwise the same certificate appears twice: once as "expiring, renew it" and once as
        // "the CSR is ready" — and the operator cannot tell whether they have already acted.
        await using var db = CreateDb();
        var certificate = Expiring(db, "renewing.example.com", days: 10);
        db.CertificateRequests.Add(new CertificateRequestEntity
        {
            Id = Guid.NewGuid(),
            CertificateId = certificate.Id,
            CommonName = "renewing.example.com",
            State = CertificateRequestState.CsrGenerated,
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1),
            UpdatedAt = DateTimeOffset.UtcNow.AddDays(-1),
        });
        await db.SaveChangesAsync();

        var items = await new WorkListService(db).BuildAsync(default);

        Assert.DoesNotContain(items, i => i.Kind == "expiring");
        var csr = Assert.Single(items, i => i.Kind == "csr-ready");
        Assert.Equal("Copy the CSR", csr.Action);
    }

    [Fact]
    public async Task A_request_waiting_at_the_ca_says_how_long_it_has_been_waiting()
    {
        await using var db = CreateDb();
        db.CertificateRequests.Add(new CertificateRequestEntity
        {
            Id = Guid.NewGuid(),
            CommonName = "slow.example.com",
            State = CertificateRequestState.PendingIssuance,
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-9),
            UpdatedAt = DateTimeOffset.UtcNow.AddDays(-9),
        });
        await db.SaveChangesAsync();

        var item = Assert.Single(await new WorkListService(db).BuildAsync(default));

        Assert.Equal("awaiting-certificate", item.Kind);
        Assert.Contains("9 day(s) ago", item.Detail);
        // Nine days of silence from a CA is not routine, and the list says so by colour.
        Assert.Equal("warning", item.Severity);
    }

    [Fact]
    public async Task Repeated_failures_of_one_installation_are_one_item()
    {
        await using var db = CreateDb();
        var certificate = Expiring(db, "retried.example.com", days: 300);
        var version = certificate.Versions.First();
        for (var i = 0; i < 4; i++)
        {
            db.DeploymentJobs.Add(new DeploymentJob
            {
                Id = Guid.NewGuid(),
                CertificateVersionId = version.Id,
                CertificateVersion = version,
                Status = DeploymentJobStatus.Failed,
                CreatedAt = DateTimeOffset.UtcNow.AddHours(-i),
            });
        }
        await db.SaveChangesAsync();

        var items = await new WorkListService(db).BuildAsync(default);

        var item = Assert.Single(items, i => i.Kind == "deployment-failed");
        Assert.Contains("3 earlier attempt(s)", item.Detail);
    }

    [Fact]
    public async Task The_most_urgent_thing_is_first()
    {
        await using var db = CreateDb();
        Expiring(db, "later.example.com", days: 80);
        Expiring(db, "sooner.example.com", days: 5);
        Expiring(db, "middling.example.com", days: 40);
        await db.SaveChangesAsync();

        var items = await new WorkListService(db).BuildAsync(default);

        Assert.Equal(
            ["sooner.example.com", "middling.example.com", "later.example.com"],
            items.Select(i => i.Title));
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"worklist-{Guid.NewGuid()}").Options);

    /// <summary>A certificate with one live version that runs out in <paramref name="days"/>.</summary>
    private static Certificate Expiring(RemoteSslDbContext db,
        string commonName, int days)
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = new Certificate
        {
            Id = Guid.NewGuid(),
            CommonName = commonName,
            DisplayName = commonName,
            HealthStatus = CertificateHealthStatus.Healthy,
            CreatedAt = now,
            UpdatedAt = now,
        };
        var version = new CertificateVersion
        {
            Id = Guid.NewGuid(),
            CertificateId = certificate.Id,
            Certificate = certificate,
            SerialNumber = Guid.NewGuid().ToString("N"),
            Sha256Thumbprint = Guid.NewGuid().ToString("N"),
            Sha1Thumbprint = Guid.NewGuid().ToString("N"),
            SubjectDn = $"CN={commonName}",
            IssuerDn = "CN=Test CA",
            NotBefore = now.AddDays(-30),
            // The service floors the difference, so land in the middle of the day it means.
            NotAfter = now.AddDays(days).AddHours(12),
            Status = CertificateVersionStatus.Active,
            PublicKeyAlgorithm = "RSA",
            KeySize = 2048,
            SignatureAlgorithm = "sha256RSA",
            CreatedAt = now,
        };
        certificate.Versions.Add(version);
        db.Certificates.Add(certificate);
        db.CertificateVersions.Add(version);
        return certificate;
    }
}
