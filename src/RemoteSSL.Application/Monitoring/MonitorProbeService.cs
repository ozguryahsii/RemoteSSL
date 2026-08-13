using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Application.Observability;
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
    INotificationSink notifier,
    ILogger<MonitorProbeService> logger,
    MetricsRecorder? metrics = null)
{
    /// <summary>Probes from the control plane (external vantage) and folds the result in.</summary>
    public async Task<MonitorEndpoint> ProbeAsync(Guid monitorId, CancellationToken ct = default)
    {
        var monitor = await db.MonitorEndpoints
                          .Include(m => m.LastObservedVersion)
                          .Include(m => m.InternalObservedVersion)
                          .FirstOrDefaultAsync(m => m.Id == monitorId, ct)
                      ?? throw new KeyNotFoundException($"Monitor {monitorId} not found");
        using var trace = TraceContext.Begin("monitor.probe");
        trace.SetTag("remotessl.monitor_id", monitor.Id);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await prober.ProbeAsync(monitor.Host, monitor.Port, monitor.Sni, ct);
        sw.Stop();
        RecordProbeLatency(monitor, sw.Elapsed.TotalMilliseconds, result.Status == ProbeStatus.Success, trace.CorrelationId);

        return await ApplyResultAsync(monitor, result, ProbeVantage.External, ct);
    }

    /// <summary>Queues a probe_latency sample (§32.1); persisted with the probe result itself.</summary>
    public void RecordProbeLatency(MonitorEndpoint monitor, double elapsedMs, bool success, string? correlationId = null)
    {
        metrics?.Record(MetricsRecorder.ProbeLatency, elapsedMs,
            $"{monitor.Host}:{monitor.Port}", success, correlationId);
    }

    /// <summary>Queues a runner-side probe job unless one is already pending for this monitor.</summary>
    public static async Task QueueRunnerProbeAsync(IRemoteSslDbContext db, MonitorEndpoint monitor, CancellationToken ct)
    {
        // jsonb columns don't support LIKE — filter candidates in memory (probe queue is small).
        var candidates = await db.RunnerJobs
            .Where(j => j.JobType == "probe" && (j.Status == "Queued" || j.Status == "Claimed"))
            .Select(j => j.PayloadJson)
            .ToListAsync(ct);
        var marker = monitor.Id.ToString();
        if (candidates.Any(p => p.Contains(marker, StringComparison.OrdinalIgnoreCase))) return;
        db.RunnerJobs.Add(new RunnerJob
        {
            Id = Guid.NewGuid(),
            RunnerId = monitor.RunnerId,
            JobType = "probe",
            PayloadJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                kind = "probe",
                monitorId = monitor.Id,
                host = monitor.Host,
                port = monitor.Port,
                sni = monitor.Sni
            }),
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow
        });
    }

    /// <summary>
    /// Folds a probe result into the inventory under the vantage it came from:
    /// external results land on the Last* fields, internal (runner) results on the
    /// Internal* fields. Both vantages feed certificate correlation, so a backend
    /// serving its own certificate still shows up in the inventory.
    /// </summary>
    public async Task<MonitorEndpoint> ApplyResultAsync(
        MonitorEndpoint monitor, TlsProbeResult result, ProbeVantage vantage, CancellationToken ct = default)
    {
        var lastSeenVersion = vantage == ProbeVantage.External ? monitor.LastObservedVersion : monitor.InternalObservedVersion;
        var lastProbeAt = vantage == ProbeVantage.External ? monitor.LastProbeAt : monitor.InternalProbeAt;
        var previousDaysLeft = lastSeenVersion is not null && lastProbeAt is not null
            ? ExpiryCalculator.DaysUntilExpiry(lastSeenVersion.NotAfter, lastProbeAt.Value)
            : (int?)null;

        var now = DateTimeOffset.UtcNow;

        if (vantage == ProbeVantage.External)
        {
            monitor.LastProbeAt = now;
            monitor.LastProbeStatus = result.Status;
            monitor.LastProbeError = result.Error;
            monitor.LastTlsProtocol = result.TlsProtocol;
            monitor.LastHostnameValid = result.HostnameValid;
            monitor.LastChainValid = result.ChainValid;
            monitor.LastChainError = result.ChainError;
        }
        else
        {
            monitor.InternalProbeAt = now;
            monitor.InternalProbeStatus = result.Status;
            monitor.InternalProbeError = result.Error;
            monitor.InternalTlsProtocol = result.TlsProtocol;
            monitor.InternalHostnameValid = result.HostnameValid;
            monitor.InternalChainValid = result.ChainValid;
            monitor.InternalChainError = result.ChainError;
        }
        monitor.UpdatedAt = now;

        if (result.Status == ProbeStatus.Success && result.LeafDer is not null)
        {
            var parsed = CertificateParser.Parse(result.LeafDer);
            var version = await CorrelateAsync(parsed, result.ChainDer, now, ct);
            if (vantage == ProbeVantage.External)
            {
                monitor.LastObservedVersionId = version.Id;
                monitor.LastObservedVersion = version;
            }
            else
            {
                monitor.InternalObservedVersionId = version.Id;
                monitor.InternalObservedVersion = version;
            }

            await UpsertMonitorLinkAsync(monitor, version.CertificateId, now, ct);
            EmitExpiryEvents(monitor, parsed, previousDaysLeft, now);

            version.Certificate.HealthStatus = ExpiryCalculator.HealthFor(parsed.NotAfter, now);
            version.Certificate.UpdatedAt = now;
        }

        await EmitVantageMismatchAsync(monitor, now, ct);
        await db.SaveChangesAsync(ct);
        return monitor;
    }

    /// <summary>Raises an audit event + notification the first time the two vantages disagree.</summary>
    private async Task EmitVantageMismatchAsync(MonitorEndpoint monitor, DateTimeOffset now, CancellationToken ct)
    {
        if (monitor.RunnerId is null) return;
        var ext = monitor.LastObservedVersion ?? (monitor.LastObservedVersionId is null ? null
            : await db.CertificateVersions.FindAsync([monitor.LastObservedVersionId], ct));
        var intr = monitor.InternalObservedVersion ?? (monitor.InternalObservedVersionId is null ? null
            : await db.CertificateVersions.FindAsync([monitor.InternalObservedVersionId], ct));

        var (verdict, detail) = VantageComparison.Compare(
            internalConfigured: true,
            monitor.LastProbeStatus, ext?.Sha256Thumbprint, ext?.NotAfter,
            monitor.InternalProbeStatus, intr?.Sha256Thumbprint, intr?.NotAfter);
        if (verdict != VantageVerdict.Mismatch) return;

        var already = await db.AuditEvents.AnyAsync(e =>
            e.Action == "vantage.mismatch" && e.ObjectId == monitor.Id.ToString()
            && e.Timestamp > now.AddHours(-24), ct);
        if (already) return;

        logger.LogWarning("Vantage mismatch on {Host}:{Port} — external {Ext}, internal {Int}",
            monitor.Host, monitor.Port, ext?.Sha256Thumbprint, intr?.Sha256Thumbprint);
        notifier.Notify("vantage.mismatch", new
        {
            host = monitor.Host, port = monitor.Port,
            external = ext?.Sha256Thumbprint, internalThumbprint = intr?.Sha256Thumbprint, detail
        });
        db.AuditEvents.Add(new AuditEvent
        {
            Timestamp = now,
            Actor = "service:monitoring",
            Action = "vantage.mismatch",
            ObjectType = "monitor_endpoint",
            ObjectId = monitor.Id.ToString(),
            Result = "MISMATCH",
            CorrelationId = Guid.NewGuid().ToString("N"),
            DetailsJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                host = monitor.Host, port = monitor.Port,
                external = ext?.Sha256Thumbprint, @internal = intr?.Sha256Thumbprint
            })
        });
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
            notifier.Notify("certificate.expiring", new
            {
                commonName = parsed.CommonName, host = monitor.Host, port = monitor.Port,
                daysLeft, threshold
            });
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
