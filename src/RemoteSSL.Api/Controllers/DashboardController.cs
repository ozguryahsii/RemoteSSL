using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Operational overview (design doc §43): critical/expiring certificates, failed
/// jobs, runner health and the renewal queue — plus the §32.1 metric set and the
/// §32.3 alert list, all in a single call so the screen stays one round-trip.
/// </summary>
[ApiController]
[Route("api/v1/dashboard")]
public class DashboardController(
    IRemoteSslDbContext db, MetricsQuery metrics, AuditPipelineHealth auditHealth,
    NotificationHealth notificationHealth)
    : ControllerBase
{
    [HttpGet]
    public async Task<object> Get(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var last24h = now.AddHours(-24);
        var last7d = now.AddDays(-7);

        // ---- Certificates: latest live version per logical certificate --------------
        var certRows = await db.Certificates.AsNoTracking()
            .Select(c => new
            {
                c.Id,
                c.CommonName,
                c.DisplayName,
                c.Environment,
                Health = c.HealthStatus,
                AutoRenew = c.RenewalPolicyId != null,
                MonitorCount = c.MonitorLinks.Count,
                DeploymentCount = db.DeploymentBindings.Count(b => b.CertificateId == c.Id),
                Latest = c.Versions
                    .Where(v => v.Status != CertificateVersionStatus.Superseded
                                && v.Status != CertificateVersionStatus.Revoked)
                    .OrderByDescending(v => v.NotAfter)
                    .Select(v => new { v.NotAfter, v.IssuerDn, v.Sha256Thumbprint })
                    .FirstOrDefault()
            })
            .ToListAsync(ct);

        var certs = certRows
            .Select(c => new
            {
                c.Id,
                c.CommonName,
                c.DisplayName,
                c.Environment,
                c.AutoRenew,
                c.MonitorCount,
                c.DeploymentCount,
                Issuer = c.Latest?.IssuerDn,
                c.Latest?.NotAfter,
                DaysLeft = c.Latest is null ? (int?)null : ExpiryCalculator.DaysUntilExpiry(c.Latest.NotAfter, now),
                Health = c.Latest is null ? c.Health.ToString() : ExpiryCalculator.HealthFor(c.Latest.NotAfter, now).ToString()
            })
            .ToList();

        // Critical/expiring list — the primary dashboard panel (§43).
        var attention = certs
            .Where(c => c.DaysLeft is not null && c.DaysLeft <= 30)
            .OrderBy(c => c.DaysLeft)
            .Take(25)
            .ToList();

        // Expiry breakdown (Faz 1 "expiry dashboard"): certificates grouped by how much
        // runway is left, so an operator sees the shape of the wave, not just two counters.
        var expiryBuckets = new[]
            {
                ("Expired", int.MinValue, -1),
                ("0-7 days", 0, 7),
                ("8-30 days", 8, 30),
                ("31-60 days", 31, 60),
                ("61-90 days", 61, 90),
                ("90+ days", 91, int.MaxValue)
            }
            .Select(b => new
            {
                Bucket = b.Item1,
                MinDays = b.Item2 == int.MinValue ? (int?)null : b.Item2,
                MaxDays = b.Item3 == int.MaxValue ? (int?)null : b.Item3,
                Count = certs.Count(c => c.DaysLeft is not null && c.DaysLeft >= b.Item2 && c.DaysLeft <= b.Item3),
                Severity = b.Item1 switch
                {
                    "Expired" or "0-7 days" => "critical",
                    "8-30 days" => "warning",
                    _ => "ok"
                }
            })
            .ToList();
        var expiryUnknown = certs.Count(c => c.DaysLeft is null);

        // ---- Deployment jobs -------------------------------------------------------
        var jobs = await db.DeploymentJobs.AsNoTracking()
            .OrderByDescending(j => j.CreatedAt).Take(200)
            .Select(j => new
            {
                j.Id,
                j.Status,
                j.Strategy,
                j.RequestedBy,
                j.CreatedAt,
                j.StartedAt,
                j.CompletedAt,
                Certificate = j.CertificateVersion.Certificate.CommonName,
                TargetCount = j.Targets.Count,
                FailedTargets = j.Targets.Count(t => t.Status == DeploymentJobStatus.Failed
                                                     || t.Status == DeploymentJobStatus.RolledBack)
            })
            .ToListAsync(ct);

        var failedStatuses = new[]
        {
            DeploymentJobStatus.Failed, DeploymentJobStatus.PartiallyFailed,
            DeploymentJobStatus.RolledBack, DeploymentJobStatus.RollbackFailed
        };
        var failedJobs = jobs.Where(j => failedStatuses.Contains(j.Status))
            .Take(15)
            .Select(j => new
            {
                j.Id,
                Status = j.Status.ToString(),
                j.Certificate,
                j.RequestedBy,
                j.TargetCount,
                j.FailedTargets,
                j.CompletedAt
            })
            .ToList();

        var finished = jobs.Where(j => j.CompletedAt is not null).ToList();
        var deploymentSuccessRate = finished.Count == 0 ? (double?)null
            : Math.Round(100.0 * finished.Count(j => j.Status == DeploymentJobStatus.Succeeded) / finished.Count, 1);
        var avgDurationSeconds = finished.Count == 0 ? (double?)null
            : Math.Round(finished.Where(j => j.StartedAt is not null)
                .Select(j => (j.CompletedAt!.Value - j.StartedAt!.Value).TotalSeconds)
                .DefaultIfEmpty(0).Average(), 1);

        // ---- Runner health ---------------------------------------------------------
        var runners = await db.Runners.AsNoTracking()
            .OrderBy(r => r.Name)
            .Select(r => new
            {
                r.Id, r.Name, r.Segment, Status = r.Status.ToString(),
                r.Version, r.LastHeartbeatAt
            })
            .ToListAsync(ct);

        var queueDepth = await db.RunnerJobs.CountAsync(j => j.Status == "Queued" || j.Status == "Claimed", ct);

        // ---- Renewal queue (§43): requests still working their way to deployment ----
        var openStates = new[]
        {
            CertificateRequestState.Draft, CertificateRequestState.Validated,
            CertificateRequestState.PendingApproval, CertificateRequestState.CsrGenerated,
            CertificateRequestState.SubmittedToCa, CertificateRequestState.PendingIssuance,
            CertificateRequestState.WaitingForCertificate, CertificateRequestState.Issued,
            CertificateRequestState.ReadyForDeployment, CertificateRequestState.RenewalDue,
            CertificateRequestState.Renewing, CertificateRequestState.FailedRetryable
        };
        var renewalQueue = await db.CertificateRequests.AsNoTracking()
            .Where(r => openStates.Contains(r.State))
            .OrderBy(r => r.CreatedAt)
            .Take(25)
            .Select(r => new
            {
                r.Id, r.CommonName, State = r.State.ToString(), r.RequestedBy,
                r.CreatedAt, r.ErrorMessage, HasCa = r.CaConnectorId != null
            })
            .ToListAsync(ct);

        var renewalFailures = await db.CertificateRequests.CountAsync(
            r => r.State == CertificateRequestState.FailedRetryable
                 || r.State == CertificateRequestState.FailedBlocked, ct);

        // ---- Monitoring / probe metrics (§32.1) ------------------------------------
        var monitors = await db.MonitorEndpoints.AsNoTracking()
            .Select(m => new { m.Id, m.Host, m.Port, m.Enabled, m.LastProbeStatus, m.LastProbeAt, m.RunnerId })
            .ToListAsync(ct);
        var probed = monitors.Where(m => m.LastProbeStatus != ProbeStatus.NeverProbed).ToList();
        var probeSuccessRate = probed.Count == 0 ? (double?)null
            : Math.Round(100.0 * probed.Count(m => m.LastProbeStatus == ProbeStatus.Success) / probed.Count, 1);

        var driftCount = await db.AuditEvents.CountAsync(
            e => (e.Action == "drift.detected" || e.Action == "vantage.mismatch") && e.Timestamp > last7d, ct);
        var rollbackCount = jobs.Count(j => j.Status is DeploymentJobStatus.RolledBack or DeploymentJobStatus.RollbackFailed);

        var pendingApprovals = await db.ApprovalRequests.AsNoTracking()
            .Where(a => a.Status == "Pending")
            .Select(a => new { a.Id, a.DeploymentJobId, a.RequestedBy, a.CreatedAt })
            .ToListAsync(ct);

        // ---- Active alerts (§32.3) -------------------------------------------------
        var alerts = new List<object>();
        void Alert(string type, string severity, string message) =>
            alerts.Add(new { Type = type, Severity = severity, Message = message });

        var criticalCerts = certs.Where(c => c.Health is "Critical" or "Expired").ToList();
        if (criticalCerts.Count > 0)
            Alert("CriticalCertificateExpiry", "critical",
                $"{criticalCerts.Count} certificate(s) expired or expiring within 7 days: " +
                string.Join(", ", criticalCerts.Take(3).Select(c => c.CommonName)));

        var partial = jobs.Count(j => j.Status == DeploymentJobStatus.PartiallyFailed);
        if (partial > 0) Alert("DeploymentPartialFailure", "warning", $"{partial} deployment job(s) finished partially failed.");

        var rollbackFailures = jobs.Count(j => j.Status == DeploymentJobStatus.RollbackFailed);
        if (rollbackFailures > 0) Alert("RollbackFailure", "critical", $"{rollbackFailures} rollback(s) failed — manual intervention required.");

        var offline = runners.Where(r => r.Status == "Offline").ToList();
        if (offline.Count > 0) Alert("RunnerOffline", "warning", $"Runner(s) offline: {string.Join(", ", offline.Select(r => r.Name))}");

        if (renewalFailures > 0) Alert("RenewalFailure", "warning", $"{renewalFailures} certificate request(s) in a failed state.");

        var caFailures = await db.CertificateRequests.CountAsync(
            r => r.ErrorMessage != null && r.UpdatedAt > last24h, ct);
        if (caFailures > 0) Alert("CaAuthenticationFailure", "warning",
            $"{caFailures} certificate request(s) reported a CA error in the last 24h.");

        var driftRecent = await db.AuditEvents.AsNoTracking()
            .Where(e => (e.Action == "drift.detected" || e.Action == "vantage.mismatch") && e.Timestamp > last24h)
            .OrderByDescending(e => e.Timestamp).Take(5)
            .Select(e => new { e.Action, e.DetailsJson, e.Timestamp })
            .ToListAsync(ct);
        if (driftRecent.Count > 0) Alert("CertificateDrift", "warning",
            $"{driftRecent.Count} drift/vantage-mismatch event(s) in the last 24h.");

        // Audit is the compliance record (§25); if its writes fail the operators must know.
        var auditFailures = auditHealth.Recent(TimeSpan.FromHours(24));
        if (auditFailures.Count > 0) Alert("AuditPipelineFailure", "critical",
            $"{auditFailures.Count} audit write(s) failed in the last 24h — last error: {auditFailures[0].Error}");

        // §33: a notification channel that stops delivering must raise its own alarm; it never
        // blocks the lifecycle, so nothing else would reveal it.
        var notificationFailures = notificationHealth.Recent(TimeSpan.FromHours(24));
        var undelivered = await db.OutboxMessages.CountAsync(m => m.Status == OutboxStatus.Failed, ct);
        if (notificationFailures.Count > 0 || undelivered > 0)
        {
            var channels = string.Join(", ", notificationHealth.CountsByChannel(TimeSpan.FromHours(24))
                .Select(c => $"{c.Key} ({c.Value})"));
            Alert("NotificationDeliveryFailure", undelivered > 0 ? "critical" : "warning",
                undelivered > 0
                    ? $"{undelivered} event(s) were never delivered after all retries. Failing channels: {channels}."
                    : $"Notification delivery is retrying. Failing channels: {channels}.");
        }

        var unreachable = monitors.Count(m => m.Enabled && m.LastProbeStatus != ProbeStatus.Success
                                              && m.LastProbeStatus != ProbeStatus.NeverProbed);
        if (unreachable > 0) Alert("ProbeFailure", "warning", $"{unreachable} monitor(s) failing their probe.");

        // ---- Latency metrics (§32.1): percentiles over the window plus a 7-day trend ---
        var probeLatency = await metrics.SummaryAsync(MetricsRecorder.ProbeLatency, TimeSpan.FromHours(24), ct);
        var caLatency = await metrics.SummaryAsync(MetricsRecorder.CaRequestLatency, TimeSpan.FromDays(7), ct);
        var probeLatencyTrend = await metrics.TrendAsync(MetricsRecorder.ProbeLatency, 7, ct);
        var caLatencyTrend = await metrics.TrendAsync(MetricsRecorder.CaRequestLatency, 7, ct);

        return new
        {
            Metrics = new
            {
                CertificatesTotal = certs.Count,
                CertificatesExpiring = certs.Count(c => c.DaysLeft is <= 30 and >= 0),
                CertificatesCritical = criticalCerts.Count,
                MonitorsTotal = monitors.Count,
                ProbeSuccessRate = probeSuccessRate,
                DeploymentSuccessRate = deploymentSuccessRate,
                DeploymentDurationSeconds = avgDurationSeconds,
                RollbackCount = rollbackCount,
                RunnersOnline = runners.Count(r => r.Status == "Online"),
                RunnersTotal = runners.Count,
                QueueDepth = queueDepth,
                RenewalFailureCount = renewalFailures,
                DriftDetectedCount = driftCount,
                PendingApprovals = pendingApprovals.Count,
                ProbeLatencyP50Ms = probeLatency.P50Ms,
                ProbeLatencyP95Ms = probeLatency.P95Ms,
                ProbeLatencySamples = probeLatency.Count,
                CaRequestLatencyP50Ms = caLatency.P50Ms,
                CaRequestLatencyP95Ms = caLatency.P95Ms,
                CaRequestLatencySamples = caLatency.Count,
                AuditPipelineFailures = auditFailures.Count,
                NotificationFailures = notificationFailures.Count,
                UndeliveredEvents = undelivered
            },
            ExpiryBuckets = expiryBuckets,
            ExpiryUnknown = expiryUnknown,
            ProbeLatencyTrend = probeLatencyTrend,
            CaRequestLatencyTrend = caLatencyTrend,
            Alerts = alerts,
            CriticalCertificates = attention,
            FailedJobs = failedJobs,
            Runners = runners,
            RenewalQueue = renewalQueue,
            PendingApprovals = pendingApprovals,
            RecentDrift = driftRecent
        };
    }
}
