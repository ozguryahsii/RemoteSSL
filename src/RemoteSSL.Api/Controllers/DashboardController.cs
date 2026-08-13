using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Operational overview (design doc §43): critical/expiring certificates, failed
/// jobs, runner health and the renewal queue — plus the §32.1 metric set and the
/// §32.3 alert list, all in a single call so the screen stays one round-trip.
/// </summary>
[ApiController]
[Route("api/v1/dashboard")]
public class DashboardController(IRemoteSslDbContext db) : ControllerBase
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

        var unreachable = monitors.Count(m => m.Enabled && m.LastProbeStatus != ProbeStatus.Success
                                              && m.LastProbeStatus != ProbeStatus.NeverProbed);
        if (unreachable > 0) Alert("ProbeFailure", "warning", $"{unreachable} monitor(s) failing their probe.");

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
                PendingApprovals = pendingApprovals.Count
            },
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
