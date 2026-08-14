using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

using RemoteSSL.Application.Observability;

namespace RemoteSSL.Application.Deployments;

/// <summary>
/// Transactional deployment orchestration (design doc §21): job creation, approval
/// gating, per-binding runner job fan-out with adapter payloads, and result
/// aggregation. One deployment per binding at a time is enforced via the queued
/// RunnerJob uniqueness check.
/// </summary>
public class DeploymentService(
    IRemoteSslDbContext db, ISecretProtector protector, AuditWriter audit,
    INotificationSink notifier, ITlsProber prober, Policies.GovernanceService governance,
    Artifacts.ArtifactService artifacts, Microsoft.Extensions.Configuration.IConfiguration configuration)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>How long a target-side backup is expected to be kept before cleanup (§31.1).</summary>
    private static readonly TimeSpan BackupRetention = TimeSpan.FromDays(30);

    /// <summary>Resolves a strategy name into its execution shape per design doc §21.4.</summary>
    private static (int MaxConcurrency, bool StopOnFailure, bool ManualContinuation) ResolveStrategy(
        string strategy, int maxConcurrency)
    {
        var s = strategy.ToLowerInvariant();
        return s switch
        {
            "all-at-once" => (0, false, false),
            "parallel" => (maxConcurrency > 0 ? maxConcurrency : 0, false, false),
            "wave" => (maxConcurrency > 0 ? maxConcurrency : 2, true, false),
            // Canary: one target, then wait for the operator before every further wave.
            "canary" => (maxConcurrency > 0 ? maxConcurrency : 1, true, true),
            "manual" => (maxConcurrency > 0 ? maxConcurrency : 1, true, true),
            // HA pair: strictly one at a time, standby member first (see HaRank).
            "ha-pair" => (1, true, false),
            _ => (1, true, false) // sequential
        };
    }

    /// <summary>
    /// Ordering rank for the HA-pair strategy (§14.3): standby members deploy first so a
    /// failure never takes down the member currently serving traffic. Targets outside a
    /// pair keep their natural position between standby and active.
    /// </summary>
    private static int HaRank(DeploymentJobTarget jt) =>
        jt.DeploymentBinding.CertificateStore.Target.HaRole?.ToLowerInvariant() switch
        {
            "standby" => 0,
            "active" => 2,
            _ => 1
        };

    public async Task<DeploymentJob> CreateJobAsync(
        Guid certificateVersionId, IReadOnlyList<Guid> bindingIds, string strategy,
        string requestedBy, bool approvalRequired, CancellationToken ct, int maxConcurrency = 0,
        string? correlationId = null)
    {
        // Inherits the trace of the renewal/request that triggered it, so the whole
        // request → CA → job → runner → target chain shares one id (§32.2).
        using var trace = TraceContext.Begin("deployment.job.create", correlationId);

        var version = await db.CertificateVersions.Include(v => v.Certificate)
                          .FirstOrDefaultAsync(v => v.Id == certificateVersionId, ct)
                      ?? throw new KeyNotFoundException("Certificate version not found");

        // §23.2: the environment governance matrix can demand approval even when the
        // caller did not ask for it. Policy may raise the bar, never lower it.
        var policy = await governance.ResolveAsync(version.CertificateId, ct);
        var environment = version.Certificate.Environment;
        if (Policies.PolicyEvaluator.RequiresApproval(policy, environment)) approvalRequired = true;

        var bindings = await db.DeploymentBindings
            .Include(b => b.CertificateStore).ThenInclude(s => s.Target)
            .Where(b => bindingIds.Contains(b.Id))
            .ToListAsync(ct);
        if (bindings.Count == 0) throw new ArgumentException("No valid deployment bindings supplied");

        // Concurrency guard: no two live jobs on the same binding (design doc §21.3).
        var live = await db.DeploymentJobs
            .Where(j => j.Status == DeploymentJobStatus.Running || j.Status == DeploymentJobStatus.Scheduled
                        || j.Status == DeploymentJobStatus.PendingApproval || j.Status == DeploymentJobStatus.Approved)
            .SelectMany(j => j.Targets.Select(t => t.DeploymentBindingId))
            .ToListAsync(ct);
        var conflict = bindingIds.FirstOrDefault(b => live.Contains(b));
        if (conflict != Guid.Empty)
            throw new InvalidOperationException($"Binding {conflict} already has an active deployment job");

        // §30.2 supply chain: refuse adapters that are not allowlisted, or whose version on
        // the assigned runner does not match the pin, before any work is queued.
        await EnsureAdaptersAllowedAsync(bindings, ct);

        var (resolvedConcurrency, stopOnFailure, manualContinuation) = ResolveStrategy(strategy, maxConcurrency);
        var job = new DeploymentJob
        {
            Id = Guid.NewGuid(),
            CertificateVersionId = version.Id,
            Status = approvalRequired ? DeploymentJobStatus.PendingApproval : DeploymentJobStatus.Approved,
            Strategy = strategy,
            MaxConcurrency = resolvedConcurrency,
            StopOnFailure = stopOnFailure,
            ManualContinuation = manualContinuation,
            RequestedBy = requestedBy,
            CorrelationId = trace.CorrelationId,
            CreatedAt = DateTimeOffset.UtcNow
        };
        foreach (var b in bindings)
        {
            job.Targets.Add(new DeploymentJobTarget
            {
                Id = Guid.NewGuid(),
                DeploymentBindingId = b.Id,
                Status = DeploymentJobStatus.Pending,
                PreviousVersionId = db.CertificateVersions
                    .Where(v => v.CertificateId == b.CertificateId && v.Status == CertificateVersionStatus.Active)
                    .Select(v => (Guid?)v.Id).FirstOrDefault()
            });
        }
        db.DeploymentJobs.Add(job);

        if (approvalRequired)
        {
            db.ApprovalRequests.Add(new ApprovalRequest
            {
                Id = Guid.NewGuid(),
                DeploymentJobId = job.Id,
                RequestedBy = requestedBy,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await UpdateCertificateStatusAsync(job, ct);
        audit.Append($"user:{requestedBy}", "deployment.create", "deployment_job", job.Id.ToString(),
            approvalRequired ? "PENDING_APPROVAL" : "CREATED",
            new { certificate = version.Certificate.CommonName, targets = bindings.Count, strategy },
            job.CorrelationId);
        notifier.Notify(Events.DomainEvents.DeploymentRequested, new
        {
            jobId = job.Id,
            certificate = version.Certificate.CommonName,
            targets = bindings.Count,
            strategy,
            environment,
            requestedBy,
            approvalRequired,
            correlationId = job.CorrelationId
        });
        await db.SaveChangesAsync(ct);
        return job;
    }

    public async Task ApproveAsync(Guid jobId, string approver, bool approve, string? reason,
        CancellationToken ct, bool approverIsBreakGlass = false)
    {
        var job = await db.DeploymentJobs.Include(j => j.CertificateVersion)
                      .FirstOrDefaultAsync(j => j.Id == jobId, ct)
                  ?? throw new KeyNotFoundException("Job not found");
        if (job.Status != DeploymentJobStatus.PendingApproval)
            throw new InvalidOperationException($"Job is {job.Status}, not awaiting approval");

        // Separation of duties (§23.3): the requester cannot approve their own change unless
        // they hold the break-glass role, and that exception is audited as such.
        var policy = await governance.ResolveAsync(job.CertificateVersion.CertificateId, ct);
        var decision = Policies.GovernanceService.CheckApprover(policy, job.RequestedBy, approver, approverIsBreakGlass);
        if (decision == Policies.ApproverDecision.SelfApprovalRefused)
            throw new InvalidOperationException("Requester cannot approve their own deployment");

        var approval = await db.ApprovalRequests.FirstOrDefaultAsync(a => a.DeploymentJobId == jobId, ct);
        if (approval is not null)
        {
            approval.Status = approve ? "Approved" : "Rejected";
            approval.DecidedBy = approver;
            approval.Reason = reason;
            approval.BreakGlass = decision == Policies.ApproverDecision.BreakGlass;
            approval.DecidedAt = DateTimeOffset.UtcNow;
        }
        job.Status = approve ? DeploymentJobStatus.Approved : DeploymentJobStatus.Cancelled;
        job.ApprovedBy = approve ? approver : null;
        audit.Append($"user:{approver}", approve ? "deployment.approve" : "deployment.reject",
            "deployment_job", jobId.ToString(),
            approve && decision == Policies.ApproverDecision.BreakGlass ? "APPROVED_BREAK_GLASS" : job.Status.ToString(),
            new { reason, breakGlass = decision == Policies.ApproverDecision.BreakGlass }, job.CorrelationId);
        notifier.Notify(approve ? Events.DomainEvents.DeploymentApproved : Events.DomainEvents.RequestRejected, new
        {
            jobId,
            approver,
            reason,
            breakGlass = decision == Policies.ApproverDecision.BreakGlass,
            correlationId = job.CorrelationId
        });
        await UpdateCertificateStatusAsync(job, ct);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Reflects the job's outcome on the certificate's lifecycle status (§19.2), so the
    /// inventory shows PendingDeployment / PartiallyDeployed / DeploymentFailed rather than
    /// expiry alone.
    /// </summary>
    private async Task UpdateCertificateStatusAsync(DeploymentJob job, CancellationToken ct)
    {
        var status = Policies.CertificateStatusResolver.FromDeployment(job.Status);
        if (status is null) return;
        var certificateId = job.CertificateVersion?.CertificateId
                            ?? await db.CertificateVersions.Where(v => v.Id == job.CertificateVersionId)
                                .Select(v => v.CertificateId).FirstAsync(ct);
        var cert = await db.Certificates.FirstOrDefaultAsync(c => c.Id == certificateId, ct);
        if (cert is null) return;
        // A revoked certificate keeps its status regardless of deployment activity.
        if (cert.HealthStatus == CertificateHealthStatus.Revoked) return;
        cert.HealthStatus = status.Value;
        cert.UpdatedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>Fans the job out into per-binding runner jobs with full adapter payloads.</summary>
    public async Task ExecuteAsync(Guid jobId, CancellationToken ct)
    {
        var job = await db.DeploymentJobs
                      .Include(j => j.CertificateVersion)
                      .Include(j => j.Targets).ThenInclude(t => t.DeploymentBinding)
                      .ThenInclude(b => b.CertificateStore).ThenInclude(s => s.Target)
                      .FirstOrDefaultAsync(j => j.Id == jobId, ct)
                  ?? throw new KeyNotFoundException("Job not found");
        if (job.Status != DeploymentJobStatus.Approved)
            throw new InvalidOperationException($"Job is {job.Status}; approval required before execution");

        // FR-014 / §23.2: environments the policy marks window-controlled may only deploy
        // inside their certificate's maintenance window — manual deployments included.
        var policy = await governance.ResolveAsync(job.CertificateVersion.CertificateId, ct);
        var cert = await db.Certificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == job.CertificateVersion.CertificateId, ct);
        if (Policies.PolicyEvaluator.RequiresMaintenanceWindow(policy, cert?.Environment))
        {
            var windowJson = cert?.RenewalPolicyId is { } rp
                ? await db.RenewalPolicies.Where(p => p.Id == rp).Select(p => p.MaintenanceWindowJson).FirstOrDefaultAsync(ct)
                : null;
            if (string.IsNullOrWhiteSpace(windowJson))
                throw new InvalidOperationException(
                    $"Policy requires a maintenance window for environment '{cert?.Environment}', " +
                    "but no window is defined on the certificate's renewal policy.");
            if (!Policies.MaintenanceWindow.IsOpen(windowJson, DateTimeOffset.UtcNow))
                throw new InvalidOperationException(
                    $"Outside the maintenance window for environment '{cert?.Environment}'.");
        }

        job.Status = DeploymentJobStatus.Running;
        job.StartedAt = DateTimeOffset.UtcNow;

        // Dispatch the first wave according to the strategy (§21.4); further waves
        // are dispatched as targets complete in CompleteRunnerJobAsync.
        var dispatched = DispatchWave(job);
        audit.Append("service:orchestrator", "deployment.execute", "deployment_job", job.Id.ToString(),
            "RUNNING", new { targets = job.Targets.Count, strategy = job.Strategy, wave = dispatched }, job.CorrelationId);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Queues runner jobs for the next batch of pending targets, honouring the job's
    /// max concurrency. Returns how many were dispatched. MaxConcurrency 0 = all at once.
    /// </summary>
    private int DispatchWave(DeploymentJob job)
    {
        var running = job.Targets.Count(t => t.Status == DeploymentJobStatus.Running);
        var pending = job.Targets.Where(t => t.Status == DeploymentJobStatus.Pending)
            .OrderBy(HaRank).ThenBy(t => t.Id).ToList();
        var slots = job.MaxConcurrency <= 0 ? pending.Count : Math.Max(0, job.MaxConcurrency - running);

        var dispatched = 0;
        foreach (var jt in pending.Take(slots))
        {
            jt.Status = DeploymentJobStatus.Running;
            jt.StartedAt = DateTimeOffset.UtcNow;
            db.RunnerJobs.Add(new RunnerJob
            {
                Id = Guid.NewGuid(),
                RunnerId = jt.DeploymentBinding.CertificateStore.Target.RunnerId,
                JobType = "deploy",
                PayloadJson = BuildPayload(job.CertificateVersion, jt),
                CorrelationId = job.CorrelationId,
                DeploymentJobTargetId = jt.Id,
                CreatedAt = DateTimeOffset.UtcNow
            });
            dispatched++;
        }
        return dispatched;
    }

    /// <summary>
    /// Adapter allowlist and version pinning (§30.2, ADR-006). Configured under
    /// Security:Adapters:Allowed and Security:Adapters:PinnedVersions; unset means unrestricted.
    /// </summary>
    private async Task EnsureAdaptersAllowedAsync(
        IReadOnlyList<DeploymentBinding> bindings, CancellationToken ct)
    {
        var allowed = configuration.GetSection("Security:Adapters:Allowed")
            .GetChildren().Select(c => c.Value).Where(v => !string.IsNullOrWhiteSpace(v)).ToArray()!;
        var pinned = configuration.GetSection("Security:Adapters:PinnedVersions")
            .GetChildren()
            .Where(c => !string.IsNullOrWhiteSpace(c.Value))
            .ToDictionary(c => c.Key, c => c.Value!);
        if (allowed.Length == 0 && pinned.Count == 0) return;

        foreach (var binding in bindings)
        {
            var target = binding.CertificateStore.Target;
            var runnerVersions = target.RunnerId is { } runnerId
                ? await db.Runners.Where(r => r.Id == runnerId)
                    .Select(r => r.AdapterVersionsJson).FirstOrDefaultAsync(ct)
                : null;

            var verdict = Security.AdapterAllowlist.Check(allowed, pinned, target.AdapterType, runnerVersions);
            if (!verdict.Allowed)
            {
                audit.Append("service:orchestrator", "deployment.adapter-refused", "target",
                    target.Id.ToString(), "BLOCKED", new { target.AdapterType, reason = verdict.Reason });
                throw new InvalidOperationException(verdict.Reason);
            }
        }
    }

    /// <summary>
    /// Cancels a job that has not started yet. Without this a job left approved but never
    /// executed keeps its bindings locked by the concurrency guard of §21.3 forever.
    /// A running job is not cancellable — its targets are mid-pipeline; roll it back instead.
    /// </summary>
    public async Task CancelAsync(Guid jobId, string requestedBy, string? reason, CancellationToken ct)
    {
        var job = await db.DeploymentJobs.Include(j => j.Targets)
                      .FirstOrDefaultAsync(j => j.Id == jobId, ct)
                  ?? throw new KeyNotFoundException("Job not found");
        if (job.Status is not (DeploymentJobStatus.PendingApproval or DeploymentJobStatus.Approved
            or DeploymentJobStatus.Scheduled or DeploymentJobStatus.Pending))
            throw new InvalidOperationException($"Job is {job.Status}; only a job that has not started can be cancelled");

        job.Status = DeploymentJobStatus.Cancelled;
        job.CompletedAt = DateTimeOffset.UtcNow;
        foreach (var t in job.Targets.Where(t => t.Status == DeploymentJobStatus.Pending))
        {
            t.Status = DeploymentJobStatus.Cancelled;
            t.CompletedAt = DateTimeOffset.UtcNow;
        }

        var approval = await db.ApprovalRequests.FirstOrDefaultAsync(a => a.DeploymentJobId == jobId, ct);
        if (approval is not null && approval.Status == "Pending")
        {
            approval.Status = "Rejected";
            approval.DecidedBy = requestedBy;
            approval.Reason = reason ?? "job cancelled";
            approval.DecidedAt = DateTimeOffset.UtcNow;
        }

        audit.Append($"user:{requestedBy}", "deployment.cancel", "deployment_job", jobId.ToString(),
            "CANCELLED", new { reason }, job.CorrelationId);
        await UpdateCertificateStatusAsync(job, ct);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Releases the next wave of a job paused by the manual/canary strategy (§21.4).
    /// Returns how many targets were dispatched.
    /// </summary>
    public async Task<int> ContinueAsync(Guid jobId, string requestedBy, CancellationToken ct)
    {
        var job = await LoadJobGraphAsync(jobId, ct);
        if (job.Status != DeploymentJobStatus.Running)
            throw new InvalidOperationException($"Job is {job.Status}; only a running job can be continued");
        if (job.Targets.Any(t => t.Status == DeploymentJobStatus.Running))
            throw new InvalidOperationException("The current wave is still running");
        if (job.Targets.All(t => t.Status != DeploymentJobStatus.Pending))
            throw new InvalidOperationException("No targets are waiting to be deployed");

        var dispatched = DispatchWave(job);
        audit.Append($"user:{requestedBy}", "deployment.continue", "deployment_job", job.Id.ToString(),
            "RUNNING", new { wave = dispatched }, job.CorrelationId);
        await db.SaveChangesAsync(ct);
        return dispatched;
    }

    /// <summary>
    /// Manual rollback (FR-018, §27.1): puts the previous certificate version back on the
    /// targets this job changed, through the same transactional pipeline — so the rollback
    /// is itself backed up, validated, reloaded and remotely verified. Targets that were
    /// already rolled back or never succeeded are left alone. Returns the new job ids;
    /// targets whose previous version has no usable key are reported as skipped.
    /// </summary>
    public async Task<(IReadOnlyList<Guid> Jobs, IReadOnlyList<string> Skipped)> RollbackAsync(
        Guid jobId, string requestedBy, CancellationToken ct)
    {
        var job = await LoadJobGraphAsync(jobId, ct);
        if (job.Status is DeploymentJobStatus.Running or DeploymentJobStatus.PendingApproval)
            throw new InvalidOperationException($"Job is {job.Status}; wait for it to finish before rolling back");

        var restorable = job.Targets
            .Where(t => t.Status == DeploymentJobStatus.Succeeded && t.PreviousVersionId is not null)
            .ToList();

        // §9.3: some adapters replace the certificate in place and keep no previous object, so
        // there is nothing to point back at. Say so per target instead of failing halfway through.
        var irreversible = restorable
            .Where(t => !AdapterCatalog.SupportsRollback(t.DeploymentBinding.CertificateStore.Target.AdapterType))
            .ToList();
        restorable = restorable.Except(irreversible).ToList();

        if (restorable.Count == 0 && irreversible.Count > 0)
            throw new InvalidOperationException(
                "Nothing to roll back: "
                + string.Join("; ", irreversible.Select(t =>
                    $"{t.DeploymentBinding.CertificateStore.Target.Name} uses "
                    + $"'{t.DeploymentBinding.CertificateStore.Target.AdapterType}', which replaces the certificate in place")));

        if (restorable.Count == 0)
            throw new InvalidOperationException(
                "Nothing to roll back: no target of this job succeeded with a recorded previous version.");

        var jobs = new List<Guid>();
        var skipped = irreversible.Select(t =>
            $"{t.DeploymentBinding.CertificateStore.Target.Name}: "
            + $"'{t.DeploymentBinding.CertificateStore.Target.AdapterType}' replaces the certificate in place, "
            + "so there is no previous object to restore").ToList();

        // One job per previous version — targets may have been on different versions.
        foreach (var group in restorable.GroupBy(t => t.PreviousVersionId!.Value))
        {
            var previous = await db.CertificateVersions.FirstOrDefaultAsync(v => v.Id == group.Key, ct);
            if (previous is null || previous.EncryptedPrivateKeyPem is null)
            {
                skipped.AddRange(group.Select(t =>
                    $"{t.DeploymentBinding.CertificateStore.Target.Name}: previous version has no private key in RemoteSSL"));
                continue;
            }

            var rollbackJob = await CreateJobAsync(
                previous.Id, group.Select(t => t.DeploymentBindingId).ToList(),
                "sequential", requestedBy, approvalRequired: false, ct,
                correlationId: string.IsNullOrWhiteSpace(job.CorrelationId) ? null : job.CorrelationId);
            rollbackJob.RolledBackFromJobId = job.Id;
            jobs.Add(rollbackJob.Id);

            notifier.Notify(Events.DomainEvents.RollbackStarted, new
            {
                jobId = job.Id,
                rollbackJobId = rollbackJob.Id,
                toVersion = previous.Id,
                targets = group.Count(),
                requestedBy,
                correlationId = job.CorrelationId
            });
            audit.Append($"user:{requestedBy}", "deployment.rollback", "deployment_job", job.Id.ToString(),
                "ROLLBACK_REQUESTED",
                new { rollbackJobId = rollbackJob.Id, toVersion = previous.Id, targets = group.Count() },
                job.CorrelationId);
        }

        if (jobs.Count == 0)
            throw new InvalidOperationException(
                "Rollback not possible: " + string.Join("; ", skipped));

        await db.SaveChangesAsync(ct);

        // Governance still applies to a rollback: in an environment that requires approval
        // the job waits for a checker (break-glass exists for incidents). Everything else
        // runs immediately.
        foreach (var id in jobs)
        {
            var status = await db.DeploymentJobs.Where(j => j.Id == id).Select(j => j.Status).FirstAsync(ct);
            if (status == DeploymentJobStatus.Approved) await ExecuteAsync(id, ct);
            else skipped.Add($"rollback job {id} is {status} — approve it to run the rollback");
        }
        return (jobs, skipped);
    }

    private async Task<DeploymentJob> LoadJobGraphAsync(Guid jobId, CancellationToken ct) =>
        await db.DeploymentJobs
            .Include(j => j.CertificateVersion)
            .Include(j => j.Targets).ThenInclude(t => t.DeploymentBinding)
                .ThenInclude(b => b.CertificateStore).ThenInclude(s => s.Target)
            .FirstOrDefaultAsync(j => j.Id == jobId, ct)
        ?? throw new KeyNotFoundException("Job not found");

    /// <summary>Runner posted a deploy result: record steps and aggregate statuses.</summary>
    public async Task CompleteRunnerJobAsync(Guid runnerJobId, bool success, bool rolledBack,
        IReadOnlyList<(string Step, bool Ok, string SafeLog)> steps, CancellationToken ct)
    {
        var rj = await db.RunnerJobs.FirstOrDefaultAsync(r => r.Id == runnerJobId, ct)
                 ?? throw new KeyNotFoundException("Runner job not found");
        rj.Status = success ? "Succeeded" : "Failed";
        rj.CompletedAt = DateTimeOffset.UtcNow;

        if (rj.DeploymentJobTargetId is { } jtId)
        {
            var jt = await db.DeploymentJobTargets
                .Include(t => t.DeploymentJob).ThenInclude(j => j.CertificateVersion)
                .Include(t => t.DeploymentJob).ThenInclude(j => j.Targets)
                    .ThenInclude(x => x.DeploymentBinding).ThenInclude(b => b.CertificateStore).ThenInclude(s => s.Target)
                .FirstAsync(t => t.Id == jtId, ct);
            foreach (var (step, ok, log) in steps)
            {
                db.DeploymentSteps.Add(new DeploymentStep
                {
                    Id = Guid.NewGuid(),
                    DeploymentJobTargetId = jtId,
                    StepType = Enum.TryParse<DeploymentStepType>(step, out var st) ? st : DeploymentStepType.Install,
                    Status = ok ? StepStatus.Succeeded : StepStatus.Failed,
                    IdempotencyKey = $"{rj.Id}:{step}",
                    SafeLog = log,
                    CompletedAt = DateTimeOffset.UtcNow
                });
            }
            // Backups the adapter left on the target are tracked as artifacts so their
            // retention is visible (§31.1) — the content stays on the target, only metadata here.
            foreach (var (_, _, log) in steps.Where(x => x.Step == "Backup" && x.Ok))
            {
                artifacts.RecordExternal("backup", Domain.ArtifactSensitivity.Backup, log, "service:orchestrator",
                    jt.DeploymentJobId, jt.DeploymentBinding.CertificateStore.TargetId,
                    jt.DeploymentJob.CertificateVersionId, BackupRetention);
            }

            // Post-deployment remote TLS verify (design doc §21.1 / FR-017): the control
            // plane independently probes the endpoint and confirms the expected thumbprint.
            var remoteVerified = true;
            if (success)
            {
                remoteVerified = await RemoteVerifyAsync(jt, rj, ct);
                if (!remoteVerified) success = false;
            }

            jt.Status = success ? DeploymentJobStatus.Succeeded
                : rolledBack ? DeploymentJobStatus.RolledBack : DeploymentJobStatus.Failed;
            jt.CompletedAt = DateTimeOffset.UtcNow;

            var job = jt.DeploymentJob;

            // §28.1 DeploymentTargetFailed: per-target, not per-job. A wave or parallel
            // deployment carries on after one server fails, so without this the failure would
            // be invisible to integrations until the whole job finished — possibly much later.
            if (!success)
                notifier.Notify(Events.DomainEvents.DeploymentTargetFailed, new
                {
                    jobId = job.Id,
                    targetId = jt.Id,
                    target = jt.DeploymentBinding.CertificateStore.Target.Name,
                    adapter = jt.DeploymentBinding.CertificateStore.Target.AdapterType,
                    environment = jt.DeploymentBinding.CertificateStore.Target.Environment,
                    rolledBack,
                    remoteVerified,
                    correlationId = job.CorrelationId
                });
            var all = job.Targets;

            // Wave orchestration (§21.4): dispatch the next batch unless we should stop.
            var anyFailed = all.Any(t => t.Status is DeploymentJobStatus.Failed or DeploymentJobStatus.RolledBack);
            var hasPending = all.Any(t => t.Status == DeploymentJobStatus.Pending);
            var waveDone = all.All(t => t.Status != DeploymentJobStatus.Running);
            if (hasPending && !(job.StopOnFailure && anyFailed))
            {
                // §21.4 manual/canary continuation: pause between waves until an operator
                // reviews the result and explicitly continues.
                if (job.ManualContinuation && waveDone)
                {
                    audit.Append("service:orchestrator", "deployment.wave-complete", "deployment_job",
                        job.Id.ToString(), "AWAITING_CONTINUE",
                        new { remaining = all.Count(t => t.Status == DeploymentJobStatus.Pending) },
                        job.CorrelationId);
                    notifier.Notify(Events.DomainEvents.DeploymentAwaitingContinue, new
                    {
                        jobId = job.Id,
                        remaining = all.Count(t => t.Status == DeploymentJobStatus.Pending),
                        correlationId = job.CorrelationId
                    });
                }
                else
                {
                    DispatchWave(job);
                }
            }

            if (all.All(t => t.Status != DeploymentJobStatus.Running))
            {
                // Stop-on-failure left some targets undispatched — cancel them.
                foreach (var pendingTarget in all.Where(t => t.Status == DeploymentJobStatus.Pending))
                {
                    pendingTarget.Status = DeploymentJobStatus.Cancelled;
                    pendingTarget.CompletedAt = DateTimeOffset.UtcNow;
                }

                job.Status = all.All(t => t.Status == DeploymentJobStatus.Succeeded) ? DeploymentJobStatus.Succeeded
                    : all.Any(t => t.Status == DeploymentJobStatus.Succeeded) ? DeploymentJobStatus.PartiallyFailed
                    : all.All(t => t.Status is DeploymentJobStatus.RolledBack or DeploymentJobStatus.Cancelled) ? DeploymentJobStatus.RolledBack
                    : DeploymentJobStatus.Failed;
                job.CompletedAt = DateTimeOffset.UtcNow;

                if (job.Status == DeploymentJobStatus.Succeeded)
                {
                    var version = await db.CertificateVersions.FirstAsync(v => v.Id == job.CertificateVersionId, ct);
                    var olds = await db.CertificateVersions
                        .Where(v => v.CertificateId == version.CertificateId && v.Id != version.Id
                                    && v.Status == CertificateVersionStatus.Active)
                        .ToListAsync(ct);
                    foreach (var o in olds) o.Status = CertificateVersionStatus.Superseded;
                    version.Status = CertificateVersionStatus.Active;
                }
                await UpdateCertificateStatusAsync(job, ct);
                audit.Append("service:orchestrator", "deployment.complete", "deployment_job",
                    job.Id.ToString(), job.Status.ToString(), null, job.CorrelationId);
                notifier.Notify(
                    job.Status == DeploymentJobStatus.Succeeded
                        ? Events.DomainEvents.DeploymentCompleted
                        : Events.DomainEvents.DeploymentFailed,
                    new { jobId = job.Id, status = job.Status.ToString(), correlationId = job.CorrelationId });
            }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Independent external verification: probe a monitor endpoint bound to this
    /// certificate and confirm it now serves the just-deployed thumbprint. When the
    /// binding carries an explicit verifyHost/verifyPort, that endpoint is probed;
    /// otherwise any monitor linked to the certificate is used. Absence of a probe
    /// target is not a failure (best-effort remote verify).
    /// </summary>
    private async Task<bool> RemoteVerifyAsync(DeploymentJobTarget jt, RunnerJob rj, CancellationToken ct)
    {
        var version = await db.CertificateVersions.FirstAsync(v => v.Id ==
            db.DeploymentJobs.Where(j => j.Id == jt.DeploymentJobId).Select(j => j.CertificateVersionId).First(), ct);

        string? host = null; int port = 443; string? sni = null;
        try
        {
            using var svc = JsonDocument.Parse(jt.DeploymentBinding.ServiceBindingJson);
            if (svc.RootElement.TryGetProperty("verifyHost", out var vh)) host = vh.GetString();
            if (svc.RootElement.TryGetProperty("verifyPort", out var vp) && vp.TryGetInt32(out var pv)) port = pv;
            if (svc.RootElement.TryGetProperty("verifySni", out var vs)) sni = vs.GetString();
        }
        catch { /* no explicit verify config */ }

        if (host is null)
        {
            var monitor = await db.MonitorCertificateLinks
                .Where(l => l.CertificateId == version.CertificateId)
                .Join(db.MonitorEndpoints, l => l.MonitorEndpointId, m => m.Id, (l, m) => m)
                .FirstOrDefaultAsync(ct);
            if (monitor is null)
            {
                RecordStep(jt.Id, rj.Id, DeploymentStepType.RemoteVerify, StepStatus.Skipped,
                    "no monitor endpoint bound to this certificate — remote verify skipped");
                return true;
            }
            host = monitor.Host; port = monitor.Port; sni = monitor.Sni;
        }

        var result = await prober.ProbeAsync(host, port, sni, ct);
        if (result.Status != ProbeStatus.Success || result.LeafDer is null)
        {
            RecordStep(jt.Id, rj.Id, DeploymentStepType.RemoteVerify, StepStatus.Failed,
                $"probe {host}:{port} failed: {result.Status} {result.Error}");
            return false;
        }
        var observed = Convert.ToHexString(SHA256.HashData(result.LeafDer));
        var ok = observed.Equals(version.Sha256Thumbprint, StringComparison.OrdinalIgnoreCase);
        RecordStep(jt.Id, rj.Id, DeploymentStepType.RemoteVerify, ok ? StepStatus.Succeeded : StepStatus.Failed,
            ok ? $"{host}:{port} serves expected sha256 {observed}"
               : $"{host}:{port} serves {observed}, expected {version.Sha256Thumbprint}");
        return ok;
    }

    private void RecordStep(Guid jtId, Guid rjId, DeploymentStepType type, StepStatus status, string safeLog) =>
        db.DeploymentSteps.Add(new DeploymentStep
        {
            Id = Guid.NewGuid(),
            DeploymentJobTargetId = jtId,
            StepType = type,
            Status = status,
            IdempotencyKey = $"{rjId}:{type}",
            SafeLog = safeLog,
            CompletedAt = DateTimeOffset.UtcNow
        });

    private string BuildPayload(CertificateVersion version, DeploymentJobTarget jt)
    {
        var store = jt.DeploymentBinding.CertificateStore;
        var target = store.Target;
        var conn = JsonDocument.Parse(target.ConnectionConfigJson).RootElement;
        var svc = JsonDocument.Parse(jt.DeploymentBinding.ServiceBindingJson).RootElement;
        var keyPem = version.EncryptedPrivateKeyPem is null ? null : protector.Unprotect(version.EncryptedPrivateKeyPem);

        string Get(JsonElement e, string prop, string fallback = "") =>
            e.TryGetProperty(prop, out var v) ? v.GetString() ?? fallback : fallback;
        int GetInt(JsonElement e, string prop, int fallback) =>
            e.TryGetProperty(prop, out var v) && v.TryGetInt32(out var i) ? i : fallback;
        bool GetBool(JsonElement e, string prop) => e.TryGetProperty(prop, out var v) && v.GetBoolean();
        var transitPassword = TempPassword();

        object payload = target.AdapterType switch
        {
            "nginx" or "apache" or "haproxy" or "generic-file" => new
            {
                kind = "linux",
                adapter = target.AdapterType,
                connection = new { host = Get(conn, "host", target.Name), port = GetInt(conn, "port", 22), useSudo = GetBool(conn, "useSudo") },
                credentialRefId = target.CredentialRefId,
                certPath = Get(svc, "certPath", store.StorePath),
                keyPath = Get(svc, "keyPath", store.StorePath.Replace(".crt", ".key").Replace(".pem", ".key")),
                chainPath = svc.TryGetProperty("chainPath", out var cp) ? cp.GetString() : null,
                bundleMode = Get(svc, "bundleMode", target.AdapterType == "haproxy" ? "combined" : "separate"),
                validateCmd = svc.TryGetProperty("validateCmd", out var vc) ? vc.GetString() : null,
                reloadCmd = svc.TryGetProperty("reloadCmd", out var rc) ? rc.GetString() : null,
                owner = svc.TryGetProperty("owner", out var ow) ? ow.GetString() : null,
                certPem = version.PemCertificate,
                keyPem,
                chainPem = version.PemChain,
                expectedSha256Thumbprint = version.Sha256Thumbprint
            },
            "generic-ssh" => new
            {
                kind = "generic-ssh",
                connection = new { host = Get(conn, "host", target.Name), port = GetInt(conn, "port", 22), useSudo = GetBool(conn, "useSudo") },
                credentialRefId = target.CredentialRefId,
                certPath = Get(svc, "certPath", store.StorePath),
                keyPath = svc.TryGetProperty("keyPath", out var gkp) ? gkp.GetString() : null,
                chainPath = svc.TryGetProperty("chainPath", out var gcp) ? gcp.GetString() : null,
                // Command templates come from the target's configuration only (§14.2).
                installCmd = svc.TryGetProperty("installCmd", out var gic) ? gic.GetString() : null,
                validateCmd = svc.TryGetProperty("validateCmd", out var gvc) ? gvc.GetString() : null,
                reloadCmd = svc.TryGetProperty("reloadCmd", out var grc) ? grc.GetString() : null,
                verifyCmd = svc.TryGetProperty("verifyCmd", out var gvfc) ? gvfc.GetString() : null,
                rollbackCmd = svc.TryGetProperty("rollbackCmd", out var grbc) ? grbc.GetString() : null,
                owner = svc.TryGetProperty("owner", out var gow) ? gow.GetString() : null,
                certPem = version.PemCertificate,
                keyPem,
                chainPem = version.PemChain,
                expectedSha256Thumbprint = version.Sha256Thumbprint
            },
            "windows-cert-store" or "iis" or "windows-ccs" => BuildWindowsPayload(version, target, store, svc, conn, keyPem),
            "java-keystore" or "java-truststore" => new
            {
                kind = "java",
                connection = new { host = Get(conn, "host", target.Name), port = GetInt(conn, "port", 22), useSudo = GetBool(conn, "useSudo") },
                credentialRefId = target.CredentialRefId,
                storePath = store.StorePath,
                storeType = Get(conn, "storeType", "JKS"),
                alias = store.Alias ?? version.Certificate?.CommonName ?? "remotessl",
                keytoolPath = svc.TryGetProperty("keytoolPath", out var kt) ? kt.GetString() : null,
                storePasswordRef = target.CredentialRefId, // resolved by runner via secret fetch
                certPem = version.PemCertificate,
                hasPrivateKey = keyPem is not null,
                pkcs12Base64 = keyPem is null ? null : Convert.ToBase64String(
                    CertificateFactory.BuildPfx(version.PemCertificate!, keyPem, version.PemChain, transitPassword)),
                pkcs12Password = keyPem is null ? null : transitPassword,
                reloadCmd = svc.TryGetProperty("reloadCmd", out var jrc) ? jrc.GetString() : null
            },
            "oracle-wallet" => new
            {
                kind = "oracle",
                connection = new { host = Get(conn, "host", target.Name), port = GetInt(conn, "port", 22), useSudo = GetBool(conn, "useSudo") },
                credentialRefId = target.CredentialRefId,
                walletPath = store.StorePath,
                orapkiPath = svc.TryGetProperty("orapkiPath", out var op) ? op.GetString() : null,
                certKind = Get(svc, "certKind", "trusted"),
                certPem = version.PemCertificate,
                reloadCmd = svc.TryGetProperty("reloadCmd", out var orc) ? orc.GetString() : null
            },
            "fortigate" or "paloalto" or "citrix-adc" or "cisco-ise" => new
            {
                kind = "vendor",
                vendor = target.AdapterType,
                managementUrl = Get(conn, "managementUrl"),
                credentialRefId = target.CredentialRefId,
                apiToken = conn.TryGetProperty("apiToken", out var at) ? at.GetString() : null,
                certObjectName = Get(svc, "certObjectName", store.Alias ?? "remotessl"),
                bindingRef = svc.TryGetProperty("bindingRef", out var br) ? br.GetString() : null,
                // §14.3 tenant/context: VDOM, virtual system or admin partition, whichever this
                // vendor calls it. The connection config names it per adapter.
                context = Get(conn, "vdom", Get(conn, "vsys", Get(conn, "partition"))),
                commit = !conn.TryGetProperty("skipCommit", out var sc) || !sc.GetBoolean(),
                certPem = version.PemCertificate,
                keyPem,
                chainPem = version.PemChain,
                allowInsecureTls = GetBool(conn, "allowInsecureTls")
            },
            "f5-bigip" => new
            {
                kind = "f5",
                managementUrl = Get(conn, "managementUrl"),
                credentialRefId = target.CredentialRefId,
                partition = Get(conn, "partition", "Common"),
                certObjectName = Get(svc, "certObjectName", store.Alias ?? "remotessl"),
                clientSslProfile = Get(svc, "clientSslProfile", store.StorePath),
                certPem = version.PemCertificate,
                keyPem,
                chainPem = version.PemChain,
                allowInsecureTls = GetBool(conn, "allowInsecureTls")
            },
            _ => throw new NotSupportedException($"Adapter '{target.AdapterType}' has no payload builder")
        };
        return JsonSerializer.Serialize(payload, Json);
    }

    private object BuildWindowsPayload(CertificateVersion version, Target target, CertificateStore store,
        JsonElement svc, JsonElement conn, string? keyPem)
    {
        if (keyPem is null)
            throw new InvalidOperationException("Windows PFX deployment requires the private key (central key origin or uploaded).");
        var pfxPassword = TempPassword();
        var pfx = CertificateFactory.BuildPfx(version.PemCertificate!, keyPem, version.PemChain, pfxPassword);
        string Get(JsonElement e, string prop, string fb = "") => e.TryGetProperty(prop, out var v) ? v.GetString() ?? fb : fb;
        var method = conn.TryGetProperty("method", out var mm) ? mm.GetString() ?? "winrm" : "winrm";
        var winrmSsl = conn.TryGetProperty("winRmUseSsl", out var ws) && ws.GetBoolean();
        var defaultPort = method == "ssh" ? 22 : (winrmSsl ? 5986 : 5985);
        return new
        {
            kind = "windows",
            method,
            winRmUseSsl = winrmSsl,
            connection = new
            {
                host = Get(conn, "host", target.Name),
                port = conn.TryGetProperty("port", out var p) && p.TryGetInt32(out var pi) ? pi : defaultPort,
                useSudo = false
            },
            credentialRefId = target.CredentialRefId,
            storePath = store.StorePath,
            pfxBase64 = Convert.ToBase64String(pfx),
            pfxPassword,
            iisSiteName = svc.TryGetProperty("iisSiteName", out var s) ? s.GetString() : null,
            iisHostHeader = svc.TryGetProperty("iisHostHeader", out var h) ? h.GetString() : null,
            iisPort = svc.TryGetProperty("iisPort", out var ip) && ip.TryGetInt32(out var ipi) ? ipi : 443,
            expectedSha1Thumbprint = version.Sha1Thumbprint,
            // §11.4: non-exportable unless the store explicitly asks otherwise, plus the service
            // identities that must be able to read the key.
            nonExportablePrivateKey = !svc.TryGetProperty("exportablePrivateKey", out var ex) || !ex.GetBoolean(),
            privateKeyReadAccounts = svc.TryGetProperty("privateKeyReadAccounts", out var acc)
                                     && acc.ValueKind == JsonValueKind.Array
                ? acc.EnumerateArray().Select(a => a.GetString() ?? string.Empty)
                    .Where(a => a.Length > 0).ToArray()
                : [],
            // §11.4 system service bindings: RDP and the WinRM HTTPS listener share the store.
            bindingTargets = svc.TryGetProperty("bindingTargets", out var bt) && bt.ValueKind == JsonValueKind.Array
                ? bt.EnumerateArray().Select(t => t.GetString() ?? string.Empty)
                    .Where(t => t.Length > 0).ToArray()
                : [],
            // §11.4 Centralized Certificate Store: when a share is configured the certificate goes
            // there by host name instead of into this machine's store.
            ccsPath = target.AdapterType == "windows-ccs"
                ? Get(svc, "ccsPath", store.StorePath)
                : svc.TryGetProperty("ccsPath", out var cc) ? cc.GetString() : null,
            ccsFileName = svc.TryGetProperty("ccsFileName", out var cf)
                ? cf.GetString()
                : version.Certificate?.CommonName,
            enableCcs = svc.TryGetProperty("enableCcs", out var ec) && ec.GetBoolean()
        };
    }

    /// <summary>Random transit password for PFX/PKCS12 staging; lives only inside the job payload.</summary>
    private static string TempPassword() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
}
