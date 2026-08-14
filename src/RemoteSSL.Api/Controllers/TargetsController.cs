using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/targets")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
public class TargetsController(IRemoteSslDbContext db, AuditWriter audit) : ControllerBase
{
    public record CreateTargetRequest(
        string Name, string TargetType, string AdapterType, string? Environment, string? OsType,
        JsonElement? ConnectionConfig, Guid? CredentialRefId, Guid? RunnerId, string? HaRole = null,
        string? TargetGroup = null);
    public record CreateStoreRequest(string StoreType, string StorePath, string? Alias, JsonElement? Config);
    public record CreateBindingRequest(Guid CertificateId, JsonElement? ServiceBinding, JsonElement? ActivationPolicy);

    [HttpGet]
    public async Task<IEnumerable<object>> List([FromQuery] PageRequest page, CancellationToken ct) =>
        await db.Targets.AsNoTracking().Include(t => t.Stores)
            .OrderBy(t => t.Name)
            .Select(t => new
            {
                t.Id, t.Name, TargetType = t.TargetType.ToString(), t.AdapterType, t.Environment, t.HaRole, t.TargetGroup,
                t.CredentialRefId, t.RunnerId, t.ConnectionConfigJson,
                Stores = t.Stores.Select(s => new { s.Id, s.StoreType, s.StorePath, s.Alias })
            }).ToPageAsync(page, Response, ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateTargetRequest req, CancellationToken ct)
    {
        if (await db.Targets.AnyAsync(t => t.Name == req.Name, ct))
            return Conflict(new ProblemDetails { Title = "Target name already exists" });
        var target = new Target
        {
            Id = Guid.NewGuid(),
            Name = req.Name,
            TargetType = Enum.TryParse<TargetType>(req.TargetType, true, out var tt) ? tt : TargetType.LinuxServer,
            AdapterType = req.AdapterType,
            Environment = req.Environment,
            OsType = req.OsType,
            ConnectionConfigJson = req.ConnectionConfig?.GetRawText() ?? "{}",
            CredentialRefId = req.CredentialRefId,
            RunnerId = req.RunnerId,
            HaRole = Normalize(req.HaRole),
            TargetGroup = string.IsNullOrWhiteSpace(req.TargetGroup) ? null : req.TargetGroup.Trim(),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.Targets.Add(target);
        audit.Append("user:api", "target.create", "target", target.Id.ToString(), "OK", new { req.Name, req.AdapterType });
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(List), new { target.Id });
    }

    public record UpdateTargetRequest(
        string? Name, string? AdapterType, string? Environment,
        JsonElement? ConnectionConfig, Guid? CredentialRefId, bool ClearCredential = false,
        string? HaRole = null, bool ClearHaRole = false,
        string? TargetGroup = null, bool ClearTargetGroup = false);

    [HttpPatch("{id:guid}")]
    public async Task<ActionResult<object>> Update(Guid id, UpdateTargetRequest req, CancellationToken ct)
    {
        var t = await db.Targets.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (t is null) return NotFound();
        if (!string.IsNullOrWhiteSpace(req.Name) && req.Name != t.Name)
        {
            if (await db.Targets.AnyAsync(x => x.Name == req.Name && x.Id != id, ct))
                return Conflict(new ProblemDetails { Title = "Target name already exists" });
            t.Name = req.Name;
        }
        if (!string.IsNullOrWhiteSpace(req.AdapterType)) t.AdapterType = req.AdapterType;
        if (req.Environment is not null) t.Environment = req.Environment;
        if (req.ConnectionConfig is not null) t.ConnectionConfigJson = req.ConnectionConfig.Value.GetRawText();
        if (req.ClearCredential) t.CredentialRefId = null;
        else if (req.CredentialRefId is not null) t.CredentialRefId = req.CredentialRefId;
        if (req.ClearHaRole) t.HaRole = null;
        else if (req.HaRole is not null) t.HaRole = Normalize(req.HaRole);
        if (req.ClearTargetGroup) t.TargetGroup = null;
        else if (!string.IsNullOrWhiteSpace(req.TargetGroup)) t.TargetGroup = req.TargetGroup.Trim();
        t.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append("user:api", "target.update", "target", id.ToString(), "OK", new { t.Name, t.AdapterType });
        await db.SaveChangesAsync(ct);
        return new { t.Id };
    }

    /// <summary>Only "standby"/"active" mean anything to the HA-pair strategy (§14.3).</summary>
    private static string? Normalize(string? haRole)
    {
        var r = haRole?.Trim().ToLowerInvariant();
        return r is "standby" or "active" ? r : null;
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var t = await db.Targets.Include(x => x.Stores).FirstOrDefaultAsync(x => x.Id == id, ct);
        if (t is null) return NotFound();
        var storeIds = t.Stores.Select(s => s.Id).ToList();
        if (await db.DeploymentBindings.AnyAsync(b => storeIds.Contains(b.CertificateStoreId), ct))
            return Conflict(new ProblemDetails { Title = "Target has deployment bindings; delete them first." });
        db.Targets.Remove(t);
        audit.Append("user:api", "target.delete", "target", id.ToString(), "OK", new { t.Name });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("stores/{storeId:guid}")]
    public async Task<IActionResult> DeleteStore(Guid storeId, CancellationToken ct)
    {
        var store = await db.CertificateStores.FirstOrDefaultAsync(s => s.Id == storeId, ct);
        if (store is null) return NotFound();
        if (await db.DeploymentBindings.AnyAsync(b => b.CertificateStoreId == storeId, ct))
            return Conflict(new ProblemDetails { Title = "Store has deployment bindings; delete them first." });
        db.CertificateStores.Remove(store);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("bindings/{bindingId:guid}")]
    public async Task<IActionResult> DeleteBinding(Guid bindingId, CancellationToken ct)
    {
        var binding = await db.DeploymentBindings.FirstOrDefaultAsync(b => b.Id == bindingId, ct);
        if (binding is null) return NotFound();
        db.DeploymentBindings.Remove(binding);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/stores")]
    public async Task<ActionResult<object>> AddStore(Guid id, CreateStoreRequest req, CancellationToken ct)
    {
        if (!await db.Targets.AnyAsync(t => t.Id == id, ct)) return NotFound();
        var store = new CertificateStore
        {
            Id = Guid.NewGuid(),
            TargetId = id,
            StoreType = req.StoreType,
            StorePath = req.StorePath,
            Alias = req.Alias,
            ConfigJson = req.Config?.GetRawText() ?? "{}",
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.CertificateStores.Add(store);
        await db.SaveChangesAsync(ct);
        return new { store.Id };
    }

    [HttpPost("stores/{storeId:guid}/bindings")]
    public async Task<ActionResult<object>> AddBinding(Guid storeId, CreateBindingRequest req, CancellationToken ct)
    {
        if (!await db.CertificateStores.AnyAsync(s => s.Id == storeId, ct)) return NotFound();
        if (!await db.Certificates.AnyAsync(c => c.Id == req.CertificateId, ct))
            return NotFound(new ProblemDetails { Title = "Certificate not found" });
        var binding = new DeploymentBinding
        {
            Id = Guid.NewGuid(),
            CertificateId = req.CertificateId,
            CertificateStoreId = storeId,
            ServiceBindingJson = req.ServiceBinding?.GetRawText() ?? "{}",
            ActivationPolicyJson = req.ActivationPolicy?.GetRawText() ?? "{}",
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.DeploymentBindings.Add(binding);
        await db.SaveChangesAsync(ct);
        return new { binding.Id };
    }

    [HttpGet("{id:guid}/bindings")]
    public async Task<IEnumerable<object>> Bindings(Guid id, CancellationToken ct) =>
        await db.DeploymentBindings.AsNoTracking()
            .Where(b => b.CertificateStore.TargetId == id)
            .Select(b => new
            {
                b.Id, b.CertificateId,
                Certificate = b.Certificate.CommonName,
                Store = new { b.CertificateStore.StoreType, b.CertificateStore.StorePath, b.CertificateStore.Alias },
                b.ServiceBindingJson
            }).ToListAsync(ct);

    /// <summary>Queues a remote store discovery runner job (design doc §27.1: GET /targets/{id}/stores).</summary>
    [HttpPost("{id:guid}/stores/discover")]
    public async Task<ActionResult<object>> DiscoverStores(Guid id, CancellationToken ct)
    {
        var target = await db.Targets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        if (target is null) return NotFound();

        var conn = JsonDocument.Parse(target.ConnectionConfigJson).RootElement;
        var isWindows = target.AdapterType is "windows-cert-store" or "iis";
        var job = new RunnerJob
        {
            Id = Guid.NewGuid(),
            RunnerId = target.RunnerId,
            JobType = "discover",
            PayloadJson = JsonSerializer.Serialize(new
            {
                kind = isWindows ? "windows" : "linux",
                adapter = target.AdapterType,
                method = conn.TryGetProperty("method", out var m) ? m.GetString() : (isWindows ? "winrm" : "ssh"),
                winRmUseSsl = conn.TryGetProperty("winRmUseSsl", out var ws) && ws.GetBoolean(),
                connection = new
                {
                    host = conn.TryGetProperty("host", out var h) ? h.GetString() : target.Name,
                    port = conn.TryGetProperty("port", out var p) && p.TryGetInt32(out var pi) ? pi : (isWindows ? 5985 : 22),
                    useSudo = false
                },
                credentialRefId = target.CredentialRefId
            }),
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.RunnerJobs.Add(job);
        audit.Append("user:api", "target.discover-stores", "target", id.ToString(), "QUEUED", null, job.CorrelationId);
        await db.SaveChangesAsync(ct);
        return Accepted(new { jobId = job.Id });
    }

    /// <summary>
    /// Queues a Java keystore inventory job (design doc §12.3). Deployment only ever touches one
    /// alias, so without this the store's other entries — old key pairs, expired trust anchors —
    /// never reach the inventory.
    /// </summary>
    [HttpPost("{id:guid}/stores/{storeId:guid}/inventory")]
    public async Task<ActionResult<object>> InventoryKeystore(Guid id, Guid storeId, CancellationToken ct)
    {
        var target = await db.Targets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        if (target is null) return NotFound();
        if (target.AdapterType is not ("java-keystore" or "java-truststore"))
            return ValidationProblem($"Adapter '{target.AdapterType}' has no keystore to inventory.");

        var store = await db.CertificateStores.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == storeId && s.TargetId == id, ct);
        if (store is null) return NotFound();

        var conn = JsonDocument.Parse(target.ConnectionConfigJson).RootElement;
        var job = new RunnerJob
        {
            Id = Guid.NewGuid(),
            RunnerId = target.RunnerId,
            JobType = "java-inventory",
            PayloadJson = JsonSerializer.Serialize(new
            {
                kind = "java",
                connection = new
                {
                    host = conn.TryGetProperty("host", out var h) ? h.GetString() : target.Name,
                    port = conn.TryGetProperty("port", out var p) && p.TryGetInt32(out var pi) ? pi : 22,
                    useSudo = conn.TryGetProperty("useSudo", out var us) && us.GetBoolean()
                },
                credentialRefId = target.CredentialRefId,
                storePath = store.StorePath,
                storeType = conn.TryGetProperty("storeType", out var st) ? st.GetString() : "JKS",
                keytoolPath = JsonDocument.Parse(store.ConfigJson).RootElement
                    .TryGetProperty("keytoolPath", out var kt) ? kt.GetString() : null
            }),
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.RunnerJobs.Add(job);
        audit.Append("user:api", "target.inventory-keystore", "certificate_store", storeId.ToString(),
            "QUEUED", new { store.StorePath }, job.CorrelationId);
        await db.SaveChangesAsync(ct);
        return Accepted(new { jobId = job.Id });
    }

    /// <summary>Queues a test-connection runner job for this target (design doc §27.1).</summary>
    [HttpPost("{id:guid}/test-connection")]
    public async Task<ActionResult<object>> TestConnection(Guid id, CancellationToken ct)
    {
        var target = await db.Targets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        if (target is null) return NotFound();

        var conn = JsonDocument.Parse(target.ConnectionConfigJson).RootElement;
        var job = new RunnerJob
        {
            Id = Guid.NewGuid(),
            RunnerId = target.RunnerId,
            JobType = "test-connection",
            PayloadJson = JsonSerializer.Serialize(new
            {
                kind = "linux",
                adapter = target.AdapterType,
                connection = new
                {
                    host = conn.TryGetProperty("host", out var h) ? h.GetString() : target.Name,
                    port = conn.TryGetProperty("port", out var p) && p.TryGetInt32(out var pi) ? pi : 22,
                    useSudo = false
                },
                credentialRefId = target.CredentialRefId
            }),
            CorrelationId = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.RunnerJobs.Add(job);
        audit.Append("user:api", "target.test-connection", "target", id.ToString(), "QUEUED", null, job.CorrelationId);
        await db.SaveChangesAsync(ct);
        return Accepted(new { jobId = job.Id });
    }

    /// <summary>Poll a queued runner job's result (test-connection etc.).</summary>
    [HttpGet("jobs/{jobId:guid}")]
    public async Task<ActionResult<object>> JobStatus(Guid jobId, CancellationToken ct)
    {
        var job = await db.RunnerJobs.AsNoTracking().FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return NotFound();
        return new { job.Id, job.JobType, job.Status, job.ResultJson, job.CreatedAt, job.CompletedAt };
    }
}
