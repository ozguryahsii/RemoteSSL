using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Ca;

namespace RemoteSSL.Api.Controllers;

/// <summary>Certificate factory operations (design doc §15). Outputs are returned, never stored.</summary>
[ApiController]
[Route("api/v1/artifacts")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "CertOps")]
public class ArtifactsController(IRemoteSslDbContext db, ISecretProtector protector,
    InventoryService inventory, AuditWriter audit) : ControllerBase
{
    public record CsrRequest(string CommonName, List<string>? Sans, string KeyAlgorithm = "RSA", int KeySizeOrCurve = 2048);
    public record BuildPfxRequest(string CertPem, string KeyPem, string? ChainPem, string Password);
    public record ParsePfxRequest(string PfxBase64, string Password);
    public record ChainRequest(string LeafPem, string IntermediatesPem, bool IncludeRoot = false);
    public record UploadCertificateRequest(string CertPem, string? KeyPem, string? ChainPem);

    [HttpPost("csr")]
    public ActionResult<object> GenerateCsr(CsrRequest req)
    {
        try
        {
            var result = CertificateFactory.GenerateCsr(req.CommonName, req.Sans ?? [req.CommonName],
                req.KeyAlgorithm, req.KeySizeOrCurve);
            return new { result.CsrPem, result.PrivateKeyPem };
        }
        catch (ArgumentException ex) { return ValidationProblem(ex.Message); }
    }

    [HttpPost("pfx")]
    public ActionResult<object> BuildPfx(BuildPfxRequest req)
    {
        try { return new { PfxBase64 = Convert.ToBase64String(CertificateFactory.BuildPfx(req.CertPem, req.KeyPem, req.ChainPem, req.Password)) }; }
        catch (Exception ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    [HttpPost("pfx/parse")]
    public ActionResult<object> ParsePfx(ParsePfxRequest req)
    {
        try
        {
            var r = CertificateFactory.ParsePfx(Convert.FromBase64String(req.PfxBase64), req.Password);
            return new { r.LeafPem, r.PrivateKeyPem, r.ChainPem };
        }
        catch (Exception ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    [HttpPost("chain")]
    public ActionResult<object> BuildChain(ChainRequest req)
    {
        try
        {
            var chain = CertificateFactory.BuildOrderedChain(req.LeafPem, req.IntermediatesPem, req.IncludeRoot);
            return new { ChainPem = chain, Valid = CertificateFactory.ValidateChainOrder(req.LeafPem, chain) };
        }
        catch (Exception ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    /// <summary>Upload an existing certificate (+ optional key/chain) into the inventory for deployment.</summary>
    [HttpPost("upload")]
    public async Task<ActionResult<object>> Upload(UploadCertificateRequest req, CancellationToken ct)
    {
        try
        {
            var version = await inventory.AddVersionAsync(req.CertPem, req.ChainPem,
                req.KeyPem is null ? null : protector.Protect(req.KeyPem),
                CertificateVersionStatus.Issued, ct);
            audit.Append("user:api", "certificate.upload", "certificate_version", version.Id.ToString(), "OK",
                new { version.Sha256Thumbprint });
            await db.SaveChangesAsync(ct);
            return new { version.Id, version.CertificateId, version.Sha256Thumbprint };
        }
        catch (Exception ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }
}

[ApiController]
[Route("api/v1/ca-connectors")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
public class CaConnectorsController(IRemoteSslDbContext db, ISecretProtector protector,
    CaConnectorFactory factory, AuditWriter audit) : ControllerBase
{
    public record CreateConnectorRequest(string Name, string ConnectorType, JsonElement? Config);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.CaConnectors.AsNoTracking()
            .Select(c => new { c.Id, c.Name, c.ConnectorType, c.Enabled, c.CreatedAt })
            .ToListAsync(ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateConnectorRequest req, CancellationToken ct)
    {
        var connector = new CaConnectorConfig
        {
            Id = Guid.NewGuid(),
            Name = req.Name,
            ConnectorType = req.ConnectorType,
            EncryptedConfigJson = protector.Protect(req.Config?.GetRawText() ?? "{}"),
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.CaConnectors.Add(connector);
        audit.Append("user:api", "ca-connector.create", "ca_connector", connector.Id.ToString(), "OK",
            new { req.Name, req.ConnectorType });
        await db.SaveChangesAsync(ct);
        return new { connector.Id };
    }

    [HttpPost("{id:guid}/test")]
    public async Task<ActionResult<object>> Test(Guid id, CancellationToken ct)
    {
        var cfg = await db.CaConnectors.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cfg is null) return NotFound();
        var result = await factory.Create(cfg.ConnectorType, cfg.EncryptedConfigJson).ValidateConnectionAsync(ct);
        return new { result.Success, result.Error };
    }

    [HttpGet("{id:guid}/profiles")]
    public async Task<ActionResult<object>> Profiles(Guid id, CancellationToken ct)
    {
        var cfg = await db.CaConnectors.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cfg is null) return NotFound();
        try
        {
            var profiles = await factory.Create(cfg.ConnectorType, cfg.EncryptedConfigJson).ListProfilesAsync(ct);
            return Ok(profiles.Select(p => new { p.ProfileId, p.DisplayName, p.AllowedKeyAlgorithms, p.MaxValidityDays, p.SupportsWildcard }));
        }
        catch (Exception ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }
}

[ApiController]
[Route("api/v1/policies")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
public class PoliciesController(IRemoteSslDbContext db, AuditWriter audit) : ControllerBase
{
    public record CreatePolicyRequest(
        string Name, int TriggerDays = 30, bool RotateKey = true, bool AutoDeploy = false,
        bool ApprovalRequired = false, JsonElement? MaintenanceWindow = null,
        Guid? CaConnectorId = null, string? ProfileId = null);
    public record AssignRequest(Guid CertificateId);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.RenewalPolicies.AsNoTracking().Select(p => new
        {
            p.Id, p.Name, p.Enabled, p.TriggerDays, p.RotateKey, p.AutoDeploy,
            p.ApprovalRequired, p.MaintenanceWindowJson, p.CaConnectorId, p.ProfileId
        }).ToListAsync(ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreatePolicyRequest req, CancellationToken ct)
    {
        var policy = new RenewalPolicy
        {
            Id = Guid.NewGuid(),
            Name = req.Name,
            TriggerDays = req.TriggerDays,
            RotateKey = req.RotateKey,
            AutoDeploy = req.AutoDeploy,
            ApprovalRequired = req.ApprovalRequired,
            MaintenanceWindowJson = req.MaintenanceWindow?.GetRawText(),
            CaConnectorId = req.CaConnectorId,
            ProfileId = req.ProfileId,
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.RenewalPolicies.Add(policy);
        await db.SaveChangesAsync(ct);
        return new { policy.Id };
    }

    [HttpPost("{id:guid}/assign")]
    public async Task<IActionResult> Assign(Guid id, AssignRequest req, CancellationToken ct)
    {
        var cert = await db.Certificates.FirstOrDefaultAsync(c => c.Id == req.CertificateId, ct);
        if (cert is null || !await db.RenewalPolicies.AnyAsync(p => p.Id == id, ct)) return NotFound();
        cert.RenewalPolicyId = id;
        cert.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append("user:api", "policy.assign", "certificate", cert.Id.ToString(), "OK", new { policyId = id });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}

[ApiController]
[Route("api/v1/audit")]
public class AuditController(IRemoteSslDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IEnumerable<object>> List([FromQuery] string? action, [FromQuery] int take = 100, CancellationToken ct = default)
    {
        var q = db.AuditEvents.AsNoTracking().OrderByDescending(e => e.Timestamp).AsQueryable();
        if (!string.IsNullOrEmpty(action)) q = q.Where(e => e.Action.StartsWith(action));
        return await q.Take(Math.Min(take, 500)).Select(e => new
        {
            e.Id, e.Timestamp, e.Actor, e.Action, e.ObjectType, e.ObjectId, e.Result, e.CorrelationId, e.DetailsJson
        }).ToListAsync(ct);
    }
}
