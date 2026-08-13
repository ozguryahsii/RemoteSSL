using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Monitoring;

/// <summary>
/// Runs one probe for a monitor endpoint and folds the result into the inventory:
/// dedup by SHA-256 thumbprint, renewal linking to the same logical certificate,
/// monitor-certificate correlation and expiry threshold events (design doc §6).
/// </summary>
public class MonitorProbeService(
    IRemoteSslDbContext db,
    ITlsProber prober,
    ILogger<MonitorProbeService> logger)
{
    public async Task<MonitorEndpoint> ProbeAsync(Guid monitorId, CancellationToken ct = default)
    {
        var monitor = await db.MonitorEndpoints
                          .Include(m => m.LastObservedVersion)
                          .FirstOrDefaultAsync(m => m.Id == monitorId, ct)
                      ?? throw new KeyNotFoundException($"Monitor {monitorId} not found");

        var previousDaysLeft = monitor is { LastObservedVersion: not null, LastProbeAt: not null }
            ? ExpiryCalculator.DaysUntilExpiry(monitor.LastObservedVersion.NotAfter, monitor.LastProbeAt.Value)
            : (int?)null;

        var result = await prober.ProbeAsync(monitor.Host, monitor.Port, monitor.Sni, ct);
        var now = DateTimeOffset.UtcNow;

        monitor.LastProbeAt = now;
        monitor.LastProbeStatus = result.Status;
        monitor.LastProbeError = result.Error;
        monitor.LastTlsProtocol = result.TlsProtocol;
        monitor.LastHostnameValid = result.HostnameValid;
        monitor.LastChainValid = result.ChainValid;
        monitor.LastChainError = result.ChainError;
        monitor.UpdatedAt = now;

        if (result.Status == ProbeStatus.Success && result.LeafDer is not null)
        {
            var parsed = CertificateParser.Parse(result.LeafDer);
            var version = await CorrelateAsync(parsed, result.ChainDer, now, ct);
            monitor.LastObservedVersionId = version.Id;
            monitor.LastObservedVersion = version;

            await UpsertMonitorLinkAsync(monitor, version.CertificateId, now, ct);
            EmitExpiryEvents(monitor, parsed, previousDaysLeft, now);

            version.Certificate.HealthStatus = ExpiryCalculator.HealthFor(parsed.NotAfter, now);
            version.Certificate.UpdatedAt = now;
        }

        await db.SaveChangesAsync(ct);
        return monitor;
    }

    /// <summary>
    /// Thumbprint dedup: the same certificate seen anywhere maps to one version; an
    /// unseen thumbprint becomes a new version of the logical certificate matching
    /// its common name (renewal), or a brand-new certificate.
    /// </summary>
    private async Task<CertificateVersion> CorrelateAsync(
        ParsedCertificate parsed, IReadOnlyList<byte[]> chainDer, DateTimeOffset now, CancellationToken ct)
    {
        var existing = await db.CertificateVersions
            .Include(v => v.Certificate)
            .FirstOrDefaultAsync(v => v.Sha256Thumbprint == parsed.Sha256Thumbprint, ct);
        if (existing is not null) return existing;

        var certificate = await db.Certificates
            .FirstOrDefaultAsync(c => c.CommonName == parsed.CommonName, ct);

        if (certificate is null)
        {
            certificate = new Certificate
            {
                Id = Guid.NewGuid(),
                CommonName = parsed.CommonName,
                DisplayName = parsed.CommonName,
                HealthStatus = CertificateHealthStatus.Unknown,
                CreatedAt = now,
                UpdatedAt = now
            };
            db.Certificates.Add(certificate);
        }
        else
        {
            // Renewal path: supersede prior observed versions of this logical cert.
            var actives = await db.CertificateVersions
                .Where(v => v.CertificateId == certificate.Id
                            && (v.Status == CertificateVersionStatus.Observed || v.Status == CertificateVersionStatus.Active)
                            && v.NotAfter < parsed.NotAfter)
                .ToListAsync(ct);
            foreach (var old in actives) old.Status = CertificateVersionStatus.Superseded;
        }

        var version = new CertificateVersion
        {
            Id = Guid.NewGuid(),
            CertificateId = certificate.Id,
            Certificate = certificate,
            SerialNumber = parsed.SerialNumber,
            Sha256Thumbprint = parsed.Sha256Thumbprint,
            Sha1Thumbprint = parsed.Sha1Thumbprint,
            SubjectDn = parsed.SubjectDn,
            IssuerDn = parsed.IssuerDn,
            NotBefore = parsed.NotBefore,
            NotAfter = parsed.NotAfter,
            PublicKeyAlgorithm = parsed.PublicKeyAlgorithm,
            KeySize = parsed.KeySize,
            SignatureAlgorithm = parsed.SignatureAlgorithm,
            Status = CertificateVersionStatus.Observed,
            PemCertificate = parsed.Pem,
            PemChain = BuildChainPem(chainDer),
            CreatedAt = now
        };
        foreach (var (type, value) in parsed.Sans)
            version.Sans.Add(new CertificateSan { Id = Guid.NewGuid(), SanType = type, Value = value });

        db.CertificateVersions.Add(version);
        return version;
    }

    private async Task UpsertMonitorLinkAsync(MonitorEndpoint monitor, Guid certificateId, DateTimeOffset now, CancellationToken ct)
    {
        var link = await db.MonitorCertificateLinks
            .FirstOrDefaultAsync(l => l.MonitorEndpointId == monitor.Id && l.CertificateId == certificateId, ct);
        if (link is null)
        {
            db.MonitorCertificateLinks.Add(new MonitorCertificateLink
            {
                MonitorEndpointId = monitor.Id,
                CertificateId = certificateId,
                Source = "probe",
                FirstSeenAt = now,
                LastSeenAt = now
            });
        }
        else
        {
            link.LastSeenAt = now;
        }
    }

    private void EmitExpiryEvents(MonitorEndpoint monitor, ParsedCertificate parsed, int? previousDaysLeft, DateTimeOffset now)
    {
        var daysLeft = ExpiryCalculator.DaysUntilExpiry(parsed.NotAfter, now);
        foreach (var threshold in ExpiryCalculator.CrossedThresholds(previousDaysLeft, daysLeft))
        {
            logger.LogWarning("Certificate {Cn} on {Host}:{Port} expires in {Days} days (T-{Threshold} crossed)",
                parsed.CommonName, monitor.Host, monitor.Port, daysLeft, threshold);
            db.AuditEvents.Add(new AuditEvent
            {
                Timestamp = now,
                Actor = "service:monitoring",
                Action = "certificate.expiring",
                ObjectType = "monitor_endpoint",
                ObjectId = monitor.Id.ToString(),
                Result = $"T-{threshold}",
                CorrelationId = Guid.NewGuid().ToString("N"),
                DetailsJson = $$"""{"commonName":"{{parsed.CommonName}}","host":"{{monitor.Host}}","port":{{monitor.Port}},"daysLeft":{{daysLeft}},"threshold":{{threshold}}}"""
            });
        }
    }

    private static string? BuildChainPem(IReadOnlyList<byte[]> chainDer)
    {
        if (chainDer.Count == 0) return null;
        return string.Join('\n', chainDer.Select(der => CertificateParser.Parse(der).Pem));
    }
}
