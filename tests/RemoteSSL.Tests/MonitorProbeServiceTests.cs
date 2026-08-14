using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

public class MonitorProbeServiceTests
{
    private sealed class NullSink : INotificationSink
    {
        public void Notify(string eventType, object payload) { }
    }

    private sealed class FakeProber : ITlsProber
    {
        public TlsProbeResult Next { get; set; } = new(ProbeStatus.ConnectionFailed, "not configured", null, [], null, null, null, null);

        public Task<TlsProbeResult> ProbeAsync(string host, int port, string? sni, CancellationToken ct,
            TimeSpan? timeout = null, int retries = 0)
            => Task.FromResult(Next);
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"probe-tests-{Guid.NewGuid()}")
            .Options);

    private static TlsProbeResult SuccessResult(byte[] der) =>
        new(ProbeStatus.Success, null, der, [], "Tls13", true, true, null);

    private static async Task<MonitorEndpoint> AddMonitor(RemoteSslDbContext db, string host, int port = 443)
    {
        var monitor = new MonitorEndpoint
        {
            Id = Guid.NewGuid(), Host = host, Port = port,
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow
        };
        db.MonitorEndpoints.Add(monitor);
        await db.SaveChangesAsync();
        return monitor;
    }

    [Fact]
    public async Task Successful_probe_creates_certificate_version_and_link()
    {
        await using var db = CreateDb();
        var prober = new FakeProber();
        var service = new MonitorProbeService(db, prober, new NullSink(), NullLogger<MonitorProbeService>.Instance);
        var monitor = await AddMonitor(db, "web.example.com");

        using var cert = CertificateParserTests.CreateSelfSigned(
            "web.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
        prober.Next = SuccessResult(cert.RawData);

        await service.ProbeAsync(monitor.Id);

        var version = Assert.Single(db.CertificateVersions);
        var logical = Assert.Single(db.Certificates);
        Assert.Equal("web.example.com", logical.CommonName);
        Assert.Equal(CertificateHealthStatus.Healthy, logical.HealthStatus);
        Assert.Equal(version.Id, db.MonitorEndpoints.Single().LastObservedVersionId);
        Assert.Single(db.MonitorCertificateLinks);
        // First observation at 59 days crosses T-90 and T-60.
        Assert.Equal(2, db.AuditEvents.Count(e => e.Action == "certificate.expiring"));
    }

    [Fact]
    public async Task Same_certificate_on_two_monitors_dedups_to_one_inventory_entry()
    {
        await using var db = CreateDb();
        var prober = new FakeProber();
        var service = new MonitorProbeService(db, prober, new NullSink(), NullLogger<MonitorProbeService>.Instance);
        var monitorA = await AddMonitor(db, "app.example.com");
        var monitorB = await AddMonitor(db, "api.example.com");

        using var shared = CertificateParserTests.CreateSelfSigned(
            "*.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(120));
        prober.Next = SuccessResult(shared.RawData);

        await service.ProbeAsync(monitorA.Id);
        await service.ProbeAsync(monitorB.Id);

        Assert.Single(db.Certificates);
        Assert.Single(db.CertificateVersions);
        Assert.Equal(2, db.MonitorCertificateLinks.Count());
    }

    [Fact]
    public async Task Renewed_certificate_creates_new_version_under_same_logical_certificate()
    {
        await using var db = CreateDb();
        var prober = new FakeProber();
        var service = new MonitorProbeService(db, prober, new NullSink(), NullLogger<MonitorProbeService>.Instance);
        var monitor = await AddMonitor(db, "shop.example.com");

        using var oldCert = CertificateParserTests.CreateSelfSigned(
            "shop.example.com", DateTimeOffset.UtcNow.AddDays(-300), DateTimeOffset.UtcNow.AddDays(20));
        prober.Next = SuccessResult(oldCert.RawData);
        await service.ProbeAsync(monitor.Id);

        using var newCert = CertificateParserTests.CreateSelfSigned(
            "shop.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        prober.Next = SuccessResult(newCert.RawData);
        await service.ProbeAsync(monitor.Id);

        var logical = Assert.Single(db.Certificates);
        Assert.Equal(2, db.CertificateVersions.Count());
        Assert.Equal(CertificateHealthStatus.Healthy, logical.HealthStatus);

        var superseded = db.CertificateVersions.Single(v => v.NotAfter < DateTimeOffset.UtcNow.AddDays(30));
        Assert.Equal(CertificateVersionStatus.Superseded, superseded.Status);
    }

    [Fact]
    public async Task Failed_probe_records_status_without_touching_inventory()
    {
        await using var db = CreateDb();
        var prober = new FakeProber
        {
            Next = new TlsProbeResult(ProbeStatus.Timeout, "connect timed out", null, [], null, null, null, null)
        };
        var service = new MonitorProbeService(db, prober, new NullSink(), NullLogger<MonitorProbeService>.Instance);
        var monitor = await AddMonitor(db, "down.example.com");

        await service.ProbeAsync(monitor.Id);

        var updated = db.MonitorEndpoints.Single();
        Assert.Equal(ProbeStatus.Timeout, updated.LastProbeStatus);
        Assert.Equal("connect timed out", updated.LastProbeError);
        Assert.NotNull(updated.LastProbeAt);
        Assert.Empty(db.Certificates);
        Assert.Empty(db.CertificateVersions);
    }
}
