using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Deployments;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Runner control plane API: bootstrap registration, heartbeat, job claim/complete
/// and execution-time credential resolution. Runners authenticate with the API key
/// issued at registration (SHA-256 hash stored server-side). mTLS termination is an
/// infrastructure concern layered in front of this in production.
/// </summary>
[ApiController]
[Route("api/v1/runners")]
[Microsoft.AspNetCore.Authorization.AllowAnonymous] // runner API-key auth, not user JWT
public class RunnersController(
    IRemoteSslDbContext db, IConfiguration config, ISecretProtector protector,
    DeploymentService deployments, AuditWriter audit,
    Application.Security.SecretBroker broker,
    Infrastructure.Security.RunnerIdentityService identities) : ControllerBase
{
    public record RegisterRequest(string BootstrapToken, string Name, string? Segment, string[] Capabilities,
        string? Version, string? CsrPem = null, Dictionary<string, string>? AdapterVersions = null,
        string? AffinityGroup = null);
    public record RegisterResponse(Guid RunnerId, string ApiKey,
        string? CertificatePem = null, string? CaCertificatePem = null);
    public record HeartbeatRequest(string[] Capabilities, string? Version,
        Dictionary<string, string>? AdapterVersions = null);
    public record CompleteRequest(bool Success, bool RolledBack, List<StepDto> Steps, string? ResultJson);
    public record StepDto(string Step, bool Success, string SafeLog);

    [HttpPost("register")]
    public async Task<ActionResult<RegisterResponse>> Register(RegisterRequest req, CancellationToken ct)
    {
        var expected = config["Runner:BootstrapToken"];
        if (string.IsNullOrEmpty(expected) || req.BootstrapToken != expected)
            return Unauthorized(new ProblemDetails { Title = "Invalid bootstrap token" });

        var apiKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var runner = await db.Runners.FirstOrDefaultAsync(r => r.Name == req.Name, ct);
        if (runner is null)
        {
            runner = new RunnerNode { Id = Guid.NewGuid(), Name = req.Name, RegisteredAt = DateTimeOffset.UtcNow };
            db.Runners.Add(runner);
        }
        runner.Segment = req.Segment;
        runner.AffinityGroup = req.AffinityGroup ?? req.Segment;
        runner.Status = RunnerStatus.Online;
        runner.CapabilitiesJson = JsonSerializer.Serialize(req.Capabilities);
        runner.Version = req.Version;
        runner.ApiKeyHash = Hash(apiKey);
        runner.LastHeartbeatAt = DateTimeOffset.UtcNow;
        runner.AdapterVersionsJson = JsonSerializer.Serialize(req.AdapterVersions ?? []);
        // Re-registering clears an earlier revocation only because the bootstrap token was
        // presented again, which is the operator deliberately re-enrolling the runner.
        runner.IdentityRevokedAt = null;
        runner.IdentityRevokedReason = null;

        // §8.2: the runner generates its own key and sends a CSR; we hand back a client
        // certificate so later calls can be authenticated by identity, not just a shared key.
        string? certificatePem = null, caPem = null;
        if (!string.IsNullOrWhiteSpace(req.CsrPem))
        {
            var identity = await identities.IssueAsync(req.Name, req.CsrPem, ct);
            runner.IdentityCertThumbprint = identity.Thumbprint;
            certificatePem = identity.CertificatePem;
            caPem = identity.CaCertificatePem;
        }

        audit.Append($"runner:{req.Name}", "runner.register", "runner", runner.Id.ToString(), "OK",
            new { req.Segment, req.Capabilities, identityIssued = certificatePem is not null });
        await db.SaveChangesAsync(ct);
        return new RegisterResponse(runner.Id, apiKey, certificatePem, caPem);
    }

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.Runners.AsNoTracking().Select(r => new
        {
            r.Id, r.Name, r.Segment, r.AffinityGroup, Status = r.Status.ToString(),
            Capabilities = r.CapabilitiesJson, r.Version, r.LastHeartbeatAt, r.RegisteredAt,
            r.AdapterVersionsJson, HasIdentityCertificate = r.IdentityCertThumbprint != null,
            r.IdentityRevokedAt, r.IdentityRevokedReason
        }).ToListAsync(ct);

    /// <summary>
    /// Revokes a runner's identity certificate (§8.2/§30.2). The runner keeps its API key but
    /// can no longer authenticate where mutual TLS is required, and re-enrolment needs the
    /// bootstrap token again.
    /// </summary>
    [HttpPost("{id:guid}/revoke-identity")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
    public async Task<IActionResult> RevokeIdentity(Guid id, [FromBody] RevokeIdentityRequest req, CancellationToken ct)
    {
        var runner = await db.Runners.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (runner is null) return NotFound();
        runner.IdentityRevokedAt = DateTimeOffset.UtcNow;
        runner.IdentityRevokedReason = req.Reason;
        runner.Status = RunnerStatus.Disabled;
        audit.Append("user:api", "runner.identity.revoke", "runner", id.ToString(), "REVOKED",
            new { runner.Name, req.Reason });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    public record RevokeIdentityRequest(string? Reason = null);

    /// <summary>The runner CA certificate, so a runner can pin the control plane's issuer.</summary>
    [HttpGet("ca-certificate")]
    public async Task<ActionResult<object>> CaCertificate(CancellationToken ct) =>
        new { CertificatePem = await identities.GetAuthorityPemAsync(ct) };

    [HttpDelete("{id:guid}")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var runner = await db.Runners.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (runner is null) return NotFound();
        var pinned = await db.Targets.Where(t => t.RunnerId == id).ToListAsync(ct);
        foreach (var t in pinned) t.RunnerId = null;
        db.Runners.Remove(runner);
        audit.Append("user:api", "runner.delete", "runner", id.ToString(), "OK", new { runner.Name });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/heartbeat")]
    public async Task<IActionResult> Heartbeat(Guid id, HeartbeatRequest req, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();
        runner.Status = RunnerStatus.Online;
        runner.LastHeartbeatAt = DateTimeOffset.UtcNow;
        runner.CapabilitiesJson = JsonSerializer.Serialize(req.Capabilities);
        runner.Version = req.Version;
        if (req.AdapterVersions is not null) runner.AdapterVersionsJson = JsonSerializer.Serialize(req.AdapterVersions);

        // A heartbeat renews the lease on whatever this runner is holding (§34.2). A long
        // deployment is not abandoned work, and it should not be reclaimed as if it were.
        var lease = DateTimeOffset.UtcNow.AddSeconds(config.GetValue("Runner:JobLeaseSeconds", 300));
        var held = await db.RunnerJobs
            .Where(j => j.RunnerId == id && (j.Status == "Claimed" || j.Status == "Running"))
            .ToListAsync(ct);
        foreach (var job in held) job.LeaseExpiresAt = lease;

        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>Claims the next queued job routed to this runner (or unpinned). 204 = nothing to do.</summary>
    [HttpPost("{id:guid}/jobs/claim")]
    public async Task<ActionResult<object>> ClaimJob(Guid id, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();

        // §34.2: a runner may only take work its affinity group can reach. Candidates are filtered
        // in the query where possible and confirmed by the shared rule, so the claim path and the
        // failover path cannot disagree about who may run what.
        var candidates = await db.RunnerJobs
            .Where(j => j.Status == "Queued" && (j.RunnerId == null || j.RunnerId == id))
            .Where(j => j.AffinityGroup == null || j.AffinityGroup == runner.AffinityGroup)
            .OrderBy(j => j.CreatedAt)
            .Take(10)
            .ToListAsync(ct);

        var job = candidates.FirstOrDefault(j => Application.Deployments.RunnerFailover.CanRun(runner, j));
        if (job is null) return NoContent();

        job.Status = "Claimed";
        job.RunnerId = id;
        job.ClaimedAt = DateTimeOffset.UtcNow;
        job.Attempts++;
        // The lease is what makes an unfinished job recoverable: a runner that dies stops renewing
        // it and the failover pass picks the work up (§34.2).
        job.LeaseExpiresAt = DateTimeOffset.UtcNow.AddSeconds(
            config.GetValue("Runner:JobLeaseSeconds", 300));
        await db.SaveChangesAsync(ct);

        // Short-lived signed execution context (design doc §8.2)
        var signature = Domain.Abstractions.JobSigner.Sign(
            config["Runner:JobSigningSecret"] ?? config["Runner:BootstrapToken"] ?? "",
            job.Id, job.PayloadJson, DateTimeOffset.UtcNow.AddMinutes(15));
        return new { job.Id, job.JobType, job.PayloadJson, job.CorrelationId, Signature = signature };
    }

    /// <summary>
    /// The runner says it is about to touch the target (§34.2). From this moment the job cannot be
    /// handed to another runner: the target may already hold a backup and a partly applied change,
    /// and repeating the job elsewhere could apply it twice. Read-only jobs never call this.
    /// </summary>
    [HttpPost("{id:guid}/jobs/{jobId:guid}/started")]
    public async Task<IActionResult> StartJob(Guid id, Guid jobId, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();
        var job = await db.RunnerJobs.FirstOrDefaultAsync(j => j.Id == jobId && j.RunnerId == id, ct);
        if (job is null) return NotFound();

        job.Status = "Running";
        job.NonReassignable = true;
        job.LeaseExpiresAt = DateTimeOffset.UtcNow.AddSeconds(
            config.GetValue("Runner:JobLeaseSeconds", 300));
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/jobs/{jobId:guid}/complete")]
    public async Task<IActionResult> CompleteJob(Guid id, Guid jobId, CompleteRequest req, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();
        var job = await db.RunnerJobs.FirstOrDefaultAsync(j => j.Id == jobId && j.RunnerId == id, ct);
        if (job is null) return NotFound();
        // The work is over one way or the other; nothing left to reclaim (§34.2).
        job.LeaseExpiresAt = null;

        job.ResultJson = req.ResultJson;
        if (job.JobType == "generate-csr" && req.Success && req.ResultJson is not null)
        {
            using var payload = JsonDocument.Parse(job.PayloadJson);
            using var result = JsonDocument.Parse(req.ResultJson);
            if (payload.RootElement.TryGetProperty("requestId", out var reqId)
                && result.RootElement.TryGetProperty("csrPem", out var csr))
            {
                var requestService = HttpContext.RequestServices
                    .GetRequiredService<Application.Requests.CertificateRequestService>();
                await requestService.AttachTargetCsrAsync(reqId.GetGuid(), csr.GetString()!, ct);
            }
        }
        if (job.JobType == "probe" && req.ResultJson is not null)
        {
            using var payload = JsonDocument.Parse(job.PayloadJson);
            using var result = JsonDocument.Parse(req.ResultJson);
            var monitorId = payload.RootElement.GetProperty("monitorId").GetGuid();
            var monitor = await db.MonitorEndpoints
                .Include(m => m.LastObservedVersion).Include(m => m.InternalObservedVersion)
                .FirstOrDefaultAsync(m => m.Id == monitorId, ct);
            if (monitor is not null)
            {
                var r = result.RootElement;
                string? GetStr(string name) => r.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                bool? GetBool(string name) => r.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetBoolean() : null;
                var probeResult = new Application.Abstractions.TlsProbeResult(
                    Enum.TryParse<ProbeStatus>(GetStr("status"), out var st) ? st : ProbeStatus.ConnectionFailed,
                    GetStr("error"),
                    GetStr("leafDerBase64") is { } leaf ? Convert.FromBase64String(leaf) : null,
                    r.TryGetProperty("chainDerBase64", out var chain) && chain.ValueKind == JsonValueKind.Array
                        ? chain.EnumerateArray().Select(x => Convert.FromBase64String(x.GetString()!)).ToList()
                        : [],
                    GetStr("tlsProtocol"), GetBool("hostnameValid"), GetBool("chainValid"), GetStr("chainError"),
                    GetStr("cipherSuite"));
                var probeService = HttpContext.RequestServices
                    .GetRequiredService<Application.Monitoring.MonitorProbeService>();
                // §32.1 probe_latency for the internal vantage, as timed by the runner.
                if (r.TryGetProperty("elapsedMs", out var elapsed) && elapsed.ValueKind == JsonValueKind.Number)
                    probeService.RecordProbeLatency(monitor, elapsed.GetDouble(),
                        probeResult.Status == ProbeStatus.Success, job.CorrelationId);
                await probeService.ApplyResultAsync(monitor, probeResult,
                    Application.Monitoring.ProbeVantage.Internal, ct);
            }
        }
        if (job.DeploymentJobTargetId is not null)
        {
            await deployments.CompleteRunnerJobAsync(jobId, req.Success, req.RolledBack,
                req.Steps.Select(s => (s.Step, s.Success, s.SafeLog)).ToList(), ct);
        }
        else
        {
            job.Status = req.Success ? "Succeeded" : "Failed";
            job.CompletedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
        }
        audit.Append($"runner:{runner.Name}", $"runner.job.{job.JobType}", "runner_job", jobId.ToString(),
            req.Success ? "SUCCESS" : "FAILED", new { steps = req.Steps.Count }, job.CorrelationId);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>
    /// Execution-time credential resolution (design doc §7.3). The broker decides whether the
    /// control plane resolves the secret and returns it to the authenticated runner, or hands back
    /// only a reference so the runner fetches it straight from the provider (ADR-003) — in that
    /// mode the plaintext never passes through here at all. Either way nothing is persisted in a
    /// job payload.
    /// </summary>
    [HttpGet("{id:guid}/credentials/{credId:guid}")]
    public async Task<ActionResult<object>> GetCredential(Guid id, Guid credId, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();

        Application.Security.ResolvedCredential resolved;
        try
        {
            resolved = await broker.ResolveForRunnerAsync(credId, $"runner:{runner.Name}", ct);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
        catch (InvalidOperationException ex)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }

        return new
        {
            resolved.Mode,
            CredentialType = resolved.CredentialType.ToString(),
            resolved.Username,
            Provider = resolved.Provider.ToString(),
            // Only set in Reference mode; the runner uses it against its own provider client.
            SecretIdentifier = resolved.Mode == "Reference" ? resolved.SecretIdentifier : null,
            Secret = resolved.Material is null
                ? null
                : System.Text.Json.JsonSerializer.Serialize(resolved.Material,
                    new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))
        };
    }

    /// <summary>
    /// API key plus, when mutual TLS is required, the client certificate the runner was issued
    /// at bootstrap. A revoked identity is refused even with a valid key (§8.2, §30.2).
    /// </summary>
    private async Task<RunnerNode?> AuthenticateAsync(Guid id, CancellationToken ct)
    {
        if (!Request.Headers.TryGetValue("X-Runner-Key", out var key)) return null;
        var runner = await db.Runners.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (runner is null || runner.ApiKeyHash != Hash(key.ToString())) return null;
        if (runner.IdentityRevokedAt is not null) return null;

        if (config.GetValue("Runner:RequireMutualTls", false))
        {
            var presented = Request.HttpContext.Connection.ClientCertificate;
            if (presented is null) return null;
            var thumbprint = Convert.ToHexString(SHA256.HashData(presented.RawData));
            if (!string.Equals(thumbprint, runner.IdentityCertThumbprint, StringComparison.OrdinalIgnoreCase))
                return null;
        }

        return runner;
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
