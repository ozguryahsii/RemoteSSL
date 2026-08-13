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
    INotificationSink notifier, ITlsProber prober)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Resolves a strategy name into (maxConcurrency, stopOnFailure) per design doc §21.4.</summary>
    private static (int MaxConcurrency, bool StopOnFailure) ResolveStrategy(string strategy, int maxConcurrency)
    {
        var s = strategy.ToLowerInvariant();
        return s switch
        {
            "all-at-once" => (0, false),
            "parallel" => (maxConcurrency > 0 ? maxConcurrency : 0, false),
            "wave" => (maxConcurrency > 0 ? maxConcurrency : 2, true),
            _ => (1, true) // sequential
        };
    }

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

        var (resolvedConcurrency, stopOnFailure) = ResolveStrategy(strategy, maxConcurrency);
        var job = new DeploymentJob
        {
            Id = Guid.NewGuid(),
            CertificateVersionId = version.Id,
            Status = approvalRequired ? DeploymentJobStatus.PendingApproval : DeploymentJobStatus.Approved,
            Strategy = strategy,
            MaxConcurrency = resolvedConcurrency,
            StopOnFailure = stopOnFailure,
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

        audit.Append($"user:{requestedBy}", "deployment.create", "deployment_job", job.Id.ToString(),
            approvalRequired ? "PENDING_APPROVAL" : "CREATED",
            new { certificate = version.Certificate.CommonName, targets = bindings.Count, strategy },
            job.CorrelationId);
        await db.SaveChangesAsync(ct);
        return job;
    }

    public async Task ApproveAsync(Guid jobId, string approver, bool approve, string? reason, CancellationToken ct)
    {
        var job = await db.DeploymentJobs.FirstOrDefaultAsync(j => j.Id == jobId, ct)
                  ?? throw new KeyNotFoundException("Job not found");
        if (job.Status != DeploymentJobStatus.PendingApproval)
            throw new InvalidOperationException($"Job is {job.Status}, not awaiting approval");
        // Separation of duties (design doc §23.3)
        if (string.Equals(job.RequestedBy, approver, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Requester cannot approve their own deployment");

        var approval = await db.ApprovalRequests.FirstOrDefaultAsync(a => a.DeploymentJobId == jobId, ct);
        if (approval is not null)
        {
            approval.Status = approve ? "Approved" : "Rejected";
            approval.DecidedBy = approver;
            approval.Reason = reason;
            approval.DecidedAt = DateTimeOffset.UtcNow;
        }
        job.Status = approve ? DeploymentJobStatus.Approved : DeploymentJobStatus.Cancelled;
        job.ApprovedBy = approve ? approver : null;
        audit.Append($"user:{approver}", approve ? "deployment.approve" : "deployment.reject",
            "deployment_job", jobId.ToString(), job.Status.ToString(), new { reason }, job.CorrelationId);
        await db.SaveChangesAsync(ct);
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
            .OrderBy(t => t.Id).ToList();
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
            var all = job.Targets;

            // Wave orchestration (§21.4): dispatch the next batch unless we should stop.
            var anyFailed = all.Any(t => t.Status is DeploymentJobStatus.Failed or DeploymentJobStatus.RolledBack);
            var hasPending = all.Any(t => t.Status == DeploymentJobStatus.Pending);
            if (hasPending && !(job.StopOnFailure && anyFailed))
            {
                DispatchWave(job);
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
                audit.Append("service:orchestrator", "deployment.complete", "deployment_job",
                    job.Id.ToString(), job.Status.ToString(), null, job.CorrelationId);
                notifier.Notify(
                    job.Status == DeploymentJobStatus.Succeeded ? "deployment.succeeded" : "deployment.failed",
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
            "windows-cert-store" or "iis" => BuildWindowsPayload(version, target, store, svc, conn, keyPem),
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
            expectedSha1Thumbprint = version.Sha1Thumbprint
        };
    }

    /// <summary>Random transit password for PFX/PKCS12 staging; lives only inside the job payload.</summary>
    private static string TempPassword() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
}
