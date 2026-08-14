using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Deployments;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Application.Requests;
using RemoteSSL.Domain;

namespace RemoteSSL.Application.Automation;

/// <summary>
/// Automation engine (design doc §20/§29): renewal triggering per policy, execution
/// of approved jobs inside maintenance windows, and drift reconciliation between
/// what monitors observe and what the inventory believes is active.
/// </summary>
public class AutomationService(
    IRemoteSslDbContext db,
    CertificateRequestService requests,
    DeploymentService deployments,
    AuditWriter audit,
    INotificationSink notifier,
    ILogger<AutomationService> logger)
{
    public async Task TickAsync(CancellationToken ct)
    {
        await requests.PollPendingAsync(ct);
        await TriggerRenewalsAsync(ct);
        await DeployIssuedRenewalsAsync(ct);
        await ExecuteApprovedJobsAsync(ct);
        await DetectDriftAsync(ct);
    }

    private async Task TriggerRenewalsAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var candidates = await db.Certificates
            .Where(c => c.RenewalPolicyId != null)
            .Select(c => new
            {
                Cert = c,
                Latest = c.Versions.Where(v => v.Status == CertificateVersionStatus.Active
                                               || v.Status == CertificateVersionStatus.Observed
                                               || v.Status == CertificateVersionStatus.Issued)
                    .OrderByDescending(v => v.NotAfter).FirstOrDefault()
            })
            .Where(x => x.Latest != null)
            .ToListAsync(ct);

        foreach (var x in candidates)
        {
            var policy = await db.RenewalPolicies.FirstOrDefaultAsync(p => p.Id == x.Cert.RenewalPolicyId, ct);
            if (policy is null || !policy.Enabled) continue;
            if (ExpiryCalculator.DaysUntilExpiry(x.Latest!.NotAfter, now) > policy.TriggerDays) continue;

            var open = await db.CertificateRequests.AnyAsync(r =>
                r.CertificateId == x.Cert.Id &&
                r.State != CertificateRequestState.Issued &&
                r.State != CertificateRequestState.Rejected &&
                r.State != CertificateRequestState.FailedBlocked, ct);
            if (open) continue;
            // Renewal already issued but not yet deployed? Skip re-request.
            var issuedNewer = await db.CertificateRequests.AnyAsync(r =>
                r.CertificateId == x.Cert.Id && r.State == CertificateRequestState.Issued
                && r.IssuedVersionId != null && r.CreatedAt > now.AddDays(-policy.TriggerDays), ct);
            if (issuedNewer) continue;

            var sans = await db.CertificateSans.Where(s => s.CertificateVersionId == x.Latest.Id && s.SanType == SanType.Dns)
                .Select(s => s.Value).ToListAsync(ct);
            logger.LogInformation("Renewal due for {Cn} ({Days} days left) — creating request",
                x.Cert.CommonName, ExpiryCalculator.DaysUntilExpiry(x.Latest.NotAfter, now));

            var req = await requests.CreateAsync(x.Cert.CommonName, sans,
                x.Latest.PublicKeyAlgorithm == "EC" ? "EC" : "RSA",
                x.Latest.PublicKeyAlgorithm == "EC" ? 256 : Math.Max(x.Latest.KeySize, 2048),
                "central", policy.CaConnectorId, policy.ProfileId, "automation", ct);
            req.CertificateId = x.Cert.Id;
            audit.Append("service:automation", "renewal.trigger", "certificate", x.Cert.Id.ToString(),
                "REQUEST_CREATED", new { x.Cert.CommonName, policy.TriggerDays });
            notifier.Notify(Events.DomainEvents.RenewalDue, new
            {
                certificateId = x.Cert.Id,
                x.Cert.CommonName,
                daysLeft = ExpiryCalculator.DaysUntilExpiry(x.Latest!.NotAfter, now),
                policy.TriggerDays,
                autoDeploy = policy.AutoDeploy
            });
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Issued renewal + autoDeploy policy → deployment job for every binding of the certificate.</summary>
    private async Task DeployIssuedRenewalsAsync(CancellationToken ct)
    {
        var issued = await db.CertificateRequests
            .Where(r => r.State == CertificateRequestState.Issued && r.IssuedVersionId != null
                        && r.CertificateId != null && r.RequestedBy == "automation")
            .ToListAsync(ct);

        foreach (var req in issued)
        {
            var cert = await db.Certificates.FirstAsync(c => c.Id == req.CertificateId, ct);
            var policy = await db.RenewalPolicies.FirstOrDefaultAsync(p => p.Id == cert.RenewalPolicyId, ct);
            if (policy is not { AutoDeploy: true }) { req.State = CertificateRequestState.ReadyForDeployment; continue; }

            var bindings = await db.DeploymentBindings.Where(b => b.CertificateId == cert.Id)
                .Select(b => b.Id).ToListAsync(ct);
            if (bindings.Count == 0) { req.State = CertificateRequestState.ReadyForDeployment; continue; }

            var hasJob = await db.DeploymentJobs.AnyAsync(j => j.CertificateVersionId == req.IssuedVersionId, ct);
            if (hasJob) { req.State = CertificateRequestState.ReadyForDeployment; continue; }

            try
            {
                // Auto-deploy stays on the renewal request's trace id (§32.2).
                await deployments.CreateJobAsync(req.IssuedVersionId!.Value, bindings, "sequential",
                    "automation", policy.ApprovalRequired, ct,
                    correlationId: string.IsNullOrWhiteSpace(req.CorrelationId) ? null : req.CorrelationId);
                req.State = CertificateRequestState.ReadyForDeployment;
            }
            catch (InvalidOperationException ex)
            {
                logger.LogWarning("Auto-deploy skipped for {Cn}: {Reason}", cert.CommonName, ex.Message);
            }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Approved jobs run when their certificate's policy maintenance window is open (or absent).</summary>
    private async Task ExecuteApprovedJobsAsync(CancellationToken ct)
    {
        var approved = await db.DeploymentJobs
            .Where(j => j.Status == DeploymentJobStatus.Approved && j.RequestedBy == "automation")
            .ToListAsync(ct);
        foreach (var job in approved)
        {
            var version = await db.CertificateVersions.FirstAsync(v => v.Id == job.CertificateVersionId, ct);
            var cert = await db.Certificates.FirstAsync(c => c.Id == version.CertificateId, ct);
            var policy = await db.RenewalPolicies.FirstOrDefaultAsync(p => p.Id == cert.RenewalPolicyId, ct);
            if (policy?.MaintenanceWindowJson is not null && !IsWindowOpen(policy.MaintenanceWindowJson, DateTimeOffset.UtcNow))
                continue;
            await deployments.ExecuteAsync(job.Id, ct);
        }
    }

    private async Task DetectDriftAsync(CancellationToken ct)
    {
        var drifted = await db.MonitorEndpoints
            .Include(m => m.LastObservedVersion)
            .Where(m => m.LastObservedVersionId != null)
            .SelectMany(m => db.MonitorCertificateLinks
                .Where(l => l.MonitorEndpointId == m.Id)
                .SelectMany(l => db.CertificateVersions
                    .Where(v => v.CertificateId == l.CertificateId && v.Status == CertificateVersionStatus.Active
                                && v.Id != m.LastObservedVersionId
                                && v.NotAfter > m.LastObservedVersion!.NotAfter)
                    .Select(v => new { Monitor = m, Expected = v })))
            .ToListAsync(ct);

        foreach (var d in drifted)
        {
            var already = await db.AuditEvents.AnyAsync(e =>
                e.Action == "drift.detected" && e.ObjectId == d.Monitor.Id.ToString()
                && e.DetailsJson.Contains(d.Expected.Sha256Thumbprint), ct);
            if (already) continue;
            logger.LogWarning("Drift: {Host}:{Port} serves an older certificate than the active version",
                d.Monitor.Host, d.Monitor.Port);
            notifier.Notify("drift.detected", new
            {
                host = d.Monitor.Host, port = d.Monitor.Port,
                observed = d.Monitor.LastObservedVersion!.Sha256Thumbprint,
                expected = d.Expected.Sha256Thumbprint
            });
            audit.Append("service:automation", "drift.detected", "monitor_endpoint", d.Monitor.Id.ToString(),
                "DRIFT", new
                {
                    host = d.Monitor.Host,
                    port = d.Monitor.Port,
                    observed = d.Monitor.LastObservedVersion!.Sha256Thumbprint,
                    expected = d.Expected.Sha256Thumbprint
                });
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Window JSON: {"days":["SUN","MON"],"start":"01:00","end":"04:00"} evaluated in UTC.</summary>
    public static bool IsWindowOpen(string windowJson, DateTimeOffset nowUtc)
        => Policies.MaintenanceWindow.IsOpen(windowJson, nowUtc);
}