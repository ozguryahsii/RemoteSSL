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
        await ExpiryScanAsync(ct);
        await requests.PollPendingAsync(ct);
        await TriggerRenewalsAsync(ct);
        await DeployIssuedRenewalsAsync(ct);
        await ExecuteApprovedJobsAsync(ct);
        await RetryFailedDeploymentsAsync(ct);
        await DetectDriftAsync(ct);
    }

    /// <summary>
    /// §29.1 expiry scan, which FR-002 depends on.
    ///
    /// Expiry alerting used to happen only where a probe observed a certificate, which meant a
    /// certificate with no monitor endpoint — one issued here and deployed to an internal target
    /// nobody probes, or simply imported — never raised a single T-90…T-1 alarm and kept whatever
    /// health it was created with, indefinitely. Expiry is a property of the certificate, not of
    /// whether someone happens to be watching it, so it is computed here from the inventory.
    /// The probe path deliberately does not emit these events; two sources would alert twice for
    /// the same threshold, each keeping its own idea of what it had already announced.
    /// </summary>
    private async Task ExpiryScanAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;

        // Revoked and superseded are terminal: their expiry is not news.
        var certificates = await db.Certificates
            .Where(c => c.HealthStatus != CertificateHealthStatus.Revoked
                        && c.HealthStatus != CertificateHealthStatus.Superseded)
            .Select(c => new
            {
                Certificate = c,
                // Any version that is not itself retired, including one merely Observed on an
                // endpoint: FR-002 covers certificates RemoteSSL discovered as much as ones it
                // issued, and the longest-lived one is what the estate actually depends on.
                NotAfter = c.Versions
                    .Where(v => v.Status != CertificateVersionStatus.Revoked
                                && v.Status != CertificateVersionStatus.Superseded)
                    .OrderByDescending(v => v.NotAfter)
                    .Select(v => (DateTimeOffset?)v.NotAfter)
                    .FirstOrDefault()
            })
            .ToListAsync(ct);

        foreach (var row in certificates)
        {
            if (row.NotAfter is not { } notAfter) continue;
            var certificate = row.Certificate;
            var daysLeft = ExpiryCalculator.DaysUntilExpiry(notAfter, now);

            // A renewal that pushed the expiry back clears the alert history, so the new version
            // alerts on its own thresholds rather than staying silent behind the old one's.
            if (certificate.LastExpiryAlertThreshold is { } alerted && daysLeft > alerted)
                certificate.LastExpiryAlertThreshold = null;

            var crossed = ExpiryCalculator.CrossedThresholds(certificate.LastExpiryAlertThreshold, daysLeft);

            // First sight of a certificate that is already inside several thresholds — an import,
            // or the first tick after this scan was introduced — reports only the most urgent one.
            // The earlier thresholds passed before RemoteSSL knew about it; announcing them now
            // would claim they just happened, and on an estate of any size the first tick would be
            // an alarm storm rather than a signal.
            if (certificate.LastExpiryAlertThreshold is null && crossed.Count > 1)
                crossed = [crossed.Min()];

            foreach (var threshold in crossed)
            {
                certificate.LastExpiryAlertThreshold = threshold;
                logger.LogWarning("Certificate {Cn} expires in {Days} days (T-{Threshold} crossed)",
                    certificate.CommonName, daysLeft, threshold);

                notifier.Notify(Events.DomainEvents.CertificateExpiring, new
                {
                    certificateId = certificate.Id,
                    commonName = certificate.CommonName,
                    environment = certificate.Environment,
                    owner = certificate.OwnerId,
                    notAfter,
                    daysLeft,
                    threshold
                });
                audit.Append("service:automation", "certificate.expiring", "certificate",
                    certificate.Id.ToString(), $"T-{threshold}",
                    new { certificate.CommonName, daysLeft, threshold, notAfter });
            }

            if (daysLeft < 0 && certificate.HealthStatus != CertificateHealthStatus.Expired)
                notifier.Notify(Events.DomainEvents.CertificateExpired, new
                {
                    certificateId = certificate.Id,
                    commonName = certificate.CommonName,
                    environment = certificate.Environment,
                    notAfter
                });

            // Deployment state (pending/partial/failed) outranks expiry-derived health, so it is
            // never overwritten here — that is the §19.2 precedence the resolver encodes.
            var derived = ExpiryCalculator.HealthFor(notAfter, now);
            if (certificate.HealthStatus != derived
                && certificate.HealthStatus is CertificateHealthStatus.Unknown
                    or CertificateHealthStatus.Healthy or CertificateHealthStatus.ExpiringSoon
                    or CertificateHealthStatus.Critical or CertificateHealthStatus.Expired)
            {
                certificate.HealthStatus = derived;
                certificate.UpdatedAt = now;
            }
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// The expiry scan on its own, so it can be exercised without the request and deployment
    /// services a full tick needs.
    /// </summary>
    public Task ExpiryScanForTestsAsync(CancellationToken ct) => ExpiryScanAsync(ct);

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

    /// <summary>
    /// §29.1 deployment retry, bounded by the §29.2 rule: a transient failure (the runner was
    /// offline, the host was briefly unreachable) is retried with backoff; an authentication
    /// failure, a thumbprint mismatch or a config-validation failure is not, because retrying
    /// those just fails again more loudly and hides a change that needs a human.
    /// </summary>
    private async Task RetryFailedDeploymentsAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;

        var failed = await db.DeploymentJobs
            .Include(j => j.Targets)
            .Where(j => j.Status == DeploymentJobStatus.Failed && j.RequestedBy == "automation"
                        && j.RetryCount < MaxDeploymentRetries && j.CompletedAt != null)
            .ToListAsync(ct);

        foreach (var job in failed)
        {
            // Exponential backoff: 5, 25, 125 minutes. Long enough that a runner restart or a
            // network blip has actually resolved before the next attempt.
            var wait = TimeSpan.FromMinutes(Math.Pow(5, job.RetryCount + 1));
            if (now - job.CompletedAt!.Value < wait) continue;

            var targetIds = job.Targets.Select(t => t.Id).ToList();
            var steps = await db.DeploymentSteps
                .Where(s => targetIds.Contains(s.DeploymentJobTargetId) && s.Status == StepStatus.Failed)
                .ToListAsync(ct);

            if (!steps.All(s => IsTransient(s.StepType)))
            {
                // Record the decision once, so an operator looking at a stuck job can see that it
                // was considered and deliberately left alone rather than forgotten.
                if (job.RetryCount == 0)
                {
                    job.RetryCount = MaxDeploymentRetries;
                    audit.Append("service:automation", "deployment.retry-declined", "deployment_job",
                        job.Id.ToString(), "MANUAL_ACTION_REQUIRED",
                        new { reason = "the failure is not transient", steps = steps.Select(s => s.StepType.ToString()) },
                        job.CorrelationId);
                }
                continue;
            }

            job.RetryCount++;
            audit.Append("service:automation", "deployment.retry", "deployment_job", job.Id.ToString(),
                $"ATTEMPT_{job.RetryCount}", new { after = wait.TotalMinutes }, job.CorrelationId);
            await db.SaveChangesAsync(ct);

            try
            {
                var retry = await deployments.CreateJobAsync(
                    job.CertificateVersionId, job.Targets.Select(t => t.DeploymentBindingId).ToList(),
                    job.Strategy, "automation", approvalRequired: false, ct,
                    job.MaxConcurrency, job.CorrelationId);
                await deployments.ExecuteAsync(retry.Id, ct);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                // A binding that is busy or gone is not something a retry can fix.
                logger.LogWarning("Deployment {Job} could not be retried: {Reason}", job.Id, ex.Message);
            }
        }
    }

    /// <summary>How many automatic attempts a transiently failed deployment gets (§29.2).</summary>
    private const int MaxDeploymentRetries = 3;

    /// <summary>
    /// Steps whose failure is plausibly a network or availability problem. Everything else —
    /// config validation, verification, rollback — means the target disagreed with us, which is
    /// not a condition that improves by asking again.
    /// </summary>
    private static bool IsTransient(DeploymentStepType step) =>
        step is DeploymentStepType.PreCheck or DeploymentStepType.PrepareUpload;

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