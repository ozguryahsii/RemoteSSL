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
    DeploymentService deployments, AuditWriter audit) : ControllerBase
{
    public record RegisterRequest(string BootstrapToken, string Name, string? Segment, string[] Capabilities, string? Version);
    public record RegisterResponse(Guid RunnerId, string ApiKey);
    public record HeartbeatRequest(string[] Capabilities, string? Version);
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
        runner.Status = RunnerStatus.Online;
        runner.CapabilitiesJson = JsonSerializer.Serialize(req.Capabilities);
        runner.Version = req.Version;
        runner.ApiKeyHash = Hash(apiKey);
        runner.LastHeartbeatAt = DateTimeOffset.UtcNow;
        audit.Append($"runner:{req.Name}", "runner.register", "runner", runner.Id.ToString(), "OK",
            new { req.Segment, req.Capabilities });
        await db.SaveChangesAsync(ct);
        return new RegisterResponse(runner.Id, apiKey);
    }

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.Runners.AsNoTracking().Select(r => new
        {
            r.Id, r.Name, r.Segment, Status = r.Status.ToString(),
            Capabilities = r.CapabilitiesJson, r.Version, r.LastHeartbeatAt, r.RegisteredAt
        }).ToListAsync(ct);

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
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>Claims the next queued job routed to this runner (or unpinned). 204 = nothing to do.</summary>
    [HttpPost("{id:guid}/jobs/claim")]
    public async Task<ActionResult<object>> ClaimJob(Guid id, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();

        var job = await db.RunnerJobs
            .Where(j => j.Status == "Queued" && (j.RunnerId == null || j.RunnerId == id))
            .OrderBy(j => j.CreatedAt)
            .FirstOrDefaultAsync(ct);
        if (job is null) return NoContent();

        job.Status = "Claimed";
        job.RunnerId = id;
        job.ClaimedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        // Short-lived signed execution context (design doc §8.2)
        var signature = Domain.Abstractions.JobSigner.Sign(
            config["Runner:JobSigningSecret"] ?? config["Runner:BootstrapToken"] ?? "",
            job.Id, job.PayloadJson, DateTimeOffset.UtcNow.AddMinutes(15));
        return new { job.Id, job.JobType, job.PayloadJson, job.CorrelationId, Signature = signature };
    }

    [HttpPost("{id:guid}/jobs/{jobId:guid}/complete")]
    public async Task<IActionResult> CompleteJob(Guid id, Guid jobId, CompleteRequest req, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();
        var job = await db.RunnerJobs.FirstOrDefaultAsync(j => j.Id == jobId && j.RunnerId == id, ct);
        if (job is null) return NotFound();

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
                    GetStr("tlsProtocol"), GetBool("hostnameValid"), GetBool("chainValid"), GetStr("chainError"));
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
    /// Execution-time credential resolution (design doc §7.3): material is returned
    /// to the authenticated runner only, never persisted in job payloads.
    /// </summary>
    [HttpGet("{id:guid}/credentials/{credId:guid}")]
    public async Task<ActionResult<object>> GetCredential(Guid id, Guid credId, CancellationToken ct)
    {
        var runner = await AuthenticateAsync(id, ct);
        if (runner is null) return Unauthorized();
        var cred = await db.CredentialRefs.AsNoTracking().FirstOrDefaultAsync(c => c.Id == credId, ct);
        if (cred is null) return NotFound();

        string secretJson;
        switch (cred.Provider)
        {
            case SecretProviderType.InternalVault when cred.EncryptedSecret is not null:
                secretJson = protector.Unprotect(cred.EncryptedSecret);
                break;
            case SecretProviderType.HashiCorpVault:
                var vault = HttpContext.RequestServices.GetRequiredService<Infrastructure.Security.VaultSecretClient>();
                var (password, key) = await vault.ReadAsync(cred.SecretIdentifier, ct);
                secretJson = System.Text.Json.JsonSerializer.Serialize(new { Password = password, PrivateKeyPem = key });
                break;
            default:
                return UnprocessableEntity(new ProblemDetails
                { Title = $"Secret provider {cred.Provider} is not yet wired; configure InternalVault or HashiCorpVault." });
        }

        audit.Append($"runner:{runner.Name}", "credential.access", "credential_ref", credId.ToString(), "OK");
        await db.SaveChangesAsync(ct);
        return new { cred.CredentialType, cred.Username, Secret = secretJson };
    }

    private async Task<RunnerNode?> AuthenticateAsync(Guid id, CancellationToken ct)
    {
        if (!Request.Headers.TryGetValue("X-Runner-Key", out var key)) return null;
        var runner = await db.Runners.FirstOrDefaultAsync(r => r.Id == id, ct);
        return runner is not null && runner.ApiKeyHash == Hash(key.ToString()) ? runner : null;
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
