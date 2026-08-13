using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Policies;
using RemoteSSL.Domain;

namespace RemoteSSL.Application.Deployments;

/// <summary>One target the plan would touch, with what it holds today.</summary>
public sealed record PlannedTarget(
    Guid BindingId, string Target, string Adapter, string? Environment, string? HaRole,
    string Store, string? Alias, string? RunnerName, string RunnerStatus,
    string? CurrentThumbprint, string? CurrentCommonName, int? CurrentDaysLeft);

/// <summary>
/// Impact preview shown before a deployment is confirmed (NFR-008: "kritik production
/// deployment öncesi plan/impact açıkça görünmeli"). It answers what changes, where, in
/// what order, what governance applies, and what would block the run.
/// </summary>
public sealed record DeploymentPlan(
    string Certificate,
    string NewThumbprint,
    DateTimeOffset NewNotAfter,
    string Strategy,
    int MaxConcurrency,
    bool StopOnFailure,
    bool ManualContinuation,
    bool ApprovalRequired,
    bool WindowRequired,
    bool WindowOpen,
    bool HasPrivateKey,
    IReadOnlyList<PlannedTarget> Targets,
    IReadOnlyList<string> Environments,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Blockers);

public class DeploymentPlanner(IRemoteSslDbContext db, GovernanceService governance)
{
    public async Task<DeploymentPlan> PlanAsync(
        Guid certificateVersionId, IReadOnlyList<Guid> bindingIds, string strategy, int maxConcurrency,
        bool approvalRequested, CancellationToken ct)
    {
        var version = await db.CertificateVersions.Include(v => v.Certificate)
                          .FirstOrDefaultAsync(v => v.Id == certificateVersionId, ct)
                      ?? throw new KeyNotFoundException("Certificate version not found");

        var bindings = await db.DeploymentBindings
            .Include(b => b.CertificateStore).ThenInclude(s => s.Target)
            .Where(b => bindingIds.Contains(b.Id))
            .ToListAsync(ct);

        var runners = await db.Runners.AsNoTracking()
            .Select(r => new { r.Id, r.Name, Status = r.Status.ToString() })
            .ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var blockers = new List<string>();

        // What each target is serving today, so the operator sees what is being replaced.
        var monitorsByCertificate = await db.MonitorCertificateLinks.AsNoTracking()
            .Where(l => l.CertificateId == version.CertificateId)
            .Select(l => l.MonitorEndpointId)
            .ToListAsync(ct);

        var targets = new List<PlannedTarget>();
        foreach (var b in bindings)
        {
            var target = b.CertificateStore.Target;
            var runner = runners.FirstOrDefault(r => r.Id == target.RunnerId);
            var currentVersion = await db.CertificateVersions.AsNoTracking()
                .Where(v => v.CertificateId == b.CertificateId && v.Status == CertificateVersionStatus.Active)
                .OrderByDescending(v => v.NotAfter)
                .Select(v => new { v.Sha256Thumbprint, v.Certificate.CommonName, v.NotAfter })
                .FirstOrDefaultAsync(ct);

            targets.Add(new PlannedTarget(
                b.Id, target.Name, target.AdapterType, target.Environment, target.HaRole,
                $"{b.CertificateStore.StoreType}:{b.CertificateStore.StorePath}", b.CertificateStore.Alias,
                runner?.Name, runner?.Status ?? "no runner assigned",
                currentVersion?.Sha256Thumbprint, currentVersion?.CommonName,
                currentVersion is null ? null : Monitoring.ExpiryCalculator.DaysUntilExpiry(currentVersion.NotAfter, now)));

            if (target.RunnerId is not null && runner?.Status != "Online")
                blockers.Add($"{target.Name}: its runner is {runner?.Status ?? "unknown"}");
            if (currentVersion?.Sha256Thumbprint == version.Sha256Thumbprint)
                warnings.Add($"{target.Name} already serves this thumbprint — the deployment would be a no-op.");
        }

        var missing = bindingIds.Where(id => bindings.All(b => b.Id != id)).ToList();
        foreach (var id in missing) blockers.Add($"binding {id} no longer exists");
        if (bindings.Count == 0) blockers.Add("No valid deployment bindings selected.");

        // Concurrency guard mirrors CreateJobAsync so the preview cannot promise a run
        // that the orchestrator would refuse (§21.3).
        var live = await db.DeploymentJobs
            .Where(j => j.Status == DeploymentJobStatus.Running || j.Status == DeploymentJobStatus.Scheduled
                        || j.Status == DeploymentJobStatus.PendingApproval || j.Status == DeploymentJobStatus.Approved)
            .SelectMany(j => j.Targets.Select(t => t.DeploymentBindingId))
            .ToListAsync(ct);
        foreach (var conflict in bindingIds.Where(live.Contains))
            blockers.Add($"binding {conflict} already has an active deployment job");

        if (version.EncryptedPrivateKeyPem is null)
            blockers.Add("This certificate version has no private key in RemoteSSL, so it cannot be deployed. "
                         + "Import the key, or use a version created from a RemoteSSL CSR.");

        var policy = await governance.ResolveAsync(version.CertificateId, ct);
        var environment = version.Certificate.Environment;
        var approvalRequired = approvalRequested || PolicyEvaluator.RequiresApproval(policy, environment);
        var windowRequired = PolicyEvaluator.RequiresMaintenanceWindow(policy, environment);
        var windowOpen = true;
        if (windowRequired)
        {
            var windowJson = version.Certificate.RenewalPolicyId is { } rp
                ? await db.RenewalPolicies.Where(p => p.Id == rp).Select(p => p.MaintenanceWindowJson).FirstOrDefaultAsync(ct)
                : null;
            if (string.IsNullOrWhiteSpace(windowJson))
            {
                windowOpen = false;
                blockers.Add($"Policy requires a maintenance window in {environment}, but none is defined "
                             + "on the certificate's renewal policy.");
            }
            else
            {
                windowOpen = MaintenanceWindow.IsOpen(windowJson, now);
                if (!windowOpen) warnings.Add($"Outside the maintenance window for {environment}; execution will be refused.");
            }
        }

        if (PolicyEvaluator.IsWeakSignature(policy, version.SignatureAlgorithm))
            blockers.Add($"Signature algorithm {version.SignatureAlgorithm} is blocked by policy.");

        if (monitorsByCertificate.Count == 0 && policy.RequirePostDeploymentProbe)
            warnings.Add("No monitor is linked to this certificate, so the post-deployment remote verify "
                         + "cannot confirm the new thumbprint from outside.");

        var (concurrency, stopOnFailure, manualContinuation) = StrategyShape(strategy, maxConcurrency);
        if (strategy.Equals("ha-pair", StringComparison.OrdinalIgnoreCase)
            && targets.All(t => string.IsNullOrWhiteSpace(t.HaRole)))
            warnings.Add("HA-pair strategy selected but no target carries an HA role; order falls back to sequential.");

        return new DeploymentPlan(
            version.Certificate.CommonName, version.Sha256Thumbprint, version.NotAfter,
            strategy, concurrency, stopOnFailure, manualContinuation,
            approvalRequired, windowRequired, windowOpen,
            version.EncryptedPrivateKeyPem is not null,
            targets,
            targets.Select(t => t.Environment).Where(e => !string.IsNullOrWhiteSpace(e)).Distinct().ToList()!,
            warnings, blockers);
    }

    /// <summary>Mirrors the orchestrator's strategy table so the preview shows the real shape (§21.4).</summary>
    private static (int MaxConcurrency, bool StopOnFailure, bool ManualContinuation) StrategyShape(
        string strategy, int maxConcurrency) => strategy.ToLowerInvariant() switch
    {
        "all-at-once" => (0, false, false),
        "parallel" => (maxConcurrency > 0 ? maxConcurrency : 0, false, false),
        "wave" => (maxConcurrency > 0 ? maxConcurrency : 2, true, false),
        "canary" => (maxConcurrency > 0 ? maxConcurrency : 1, true, true),
        "manual" => (maxConcurrency > 0 ? maxConcurrency : 1, true, true),
        "ha-pair" => (1, true, false),
        _ => (1, true, false)
    };
}
