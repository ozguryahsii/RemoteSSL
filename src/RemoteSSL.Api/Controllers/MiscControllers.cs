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
    InventoryService inventory, AuditWriter audit, Application.Artifacts.ArtifactService artifacts)
    : ControllerBase
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

    public record ConvertRequest(
        string To, string? CertPem = null, string? KeyPem = null, string? ChainPem = null,
        string? PfxBase64 = null, string? P7bBase64 = null, string? Password = null, string? Alias = null,
        bool Store = false, Guid? CertificateVersionId = null);

    /// <summary>
    /// One conversion surface across every supported artifact format (§27.1, FR-006).
    /// The result can optionally be stored as a classified, envelope-encrypted artifact
    /// instead of being returned inline — key-bearing output then gets a TTL (§31.1).
    /// </summary>
    [HttpPost("convert")]
    public async Task<ActionResult<object>> ConvertFormat(ConvertRequest req, CancellationToken ct)
    {
        try
        {
            var certPem = req.CertPem;
            var chainPem = req.ChainPem;
            var keyPem = req.KeyPem;
            var keyCameFromInventory = false;

            // Convert a stored version without shipping its PEM to the caller and back.
            if (req.CertificateVersionId is { } versionId && certPem is null)
            {
                var version = await db.CertificateVersions.AsNoTracking()
                    .FirstOrDefaultAsync(v => v.Id == versionId, ct);
                if (version is null) return NotFound(new ProblemDetails { Title = "Certificate version not found" });
                certPem = version.PemCertificate;
                chainPem ??= version.PemChain;
                if (keyPem is null && version.EncryptedPrivateKeyPem is not null)
                {
                    keyPem = protector.Unprotect(version.EncryptedPrivateKeyPem);
                    keyCameFromInventory = true;
                }
            }

            var result = FormatConverter.Convert(
                req.To, certPem, keyPem, chainPem,
                req.PfxBase64 is null ? null : Convert.FromBase64String(req.PfxBase64),
                req.P7bBase64 is null ? null : Convert.FromBase64String(req.P7bBase64),
                req.Password, req.Alias);

            // A key RemoteSSL holds must not leave over the API (§7.3 / §22.3). Such a
            // conversion may still be produced — it just has to land in the encrypted
            // artifact store instead of the response body.
            if (!req.Store && result.ContainsPrivateKey && keyCameFromInventory)
            {
                return UnprocessableEntity(new ProblemDetails
                {
                    Title = "This output contains the private key RemoteSSL holds, so it cannot be returned "
                            + "over the API. Re-run with store=true to keep it as an encrypted artifact."
                });
            }

            if (!req.Store)
            {
                return new
                {
                    req.To,
                    result.ContentType,
                    result.ContainsPrivateKey,
                    ContentBase64 = Convert.ToBase64String(result.Content)
                };
            }

            var sensitivity = result.ContainsPrivateKey
                ? (req.To.Equals("key", StringComparison.OrdinalIgnoreCase)
                    ? ArtifactSensitivity.HighlySensitive
                    : ArtifactSensitivity.Sensitive)
                : ArtifactSensitivity.Public;
            var stored = await artifacts.StoreAsync(req.To.ToLowerInvariant(), sensitivity,
                $"converted.{result.FileExtension}", result.ContentType, result.Content, "api", ct,
                certificateVersionId: req.CertificateVersionId);
            return new
            {
                stored.Id, stored.FileName, stored.Sha256, stored.SizeBytes,
                Sensitivity = sensitivity.ToString(), stored.ExpiresAt, stored.StorageProvider
            };
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                                       or System.Security.Cryptography.CryptographicException or FormatException)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }
    }

    public record ChainAnalysisRequest(string LeafPem, string? PoolPem);

    /// <summary>
    /// Chain analysis (§15.3): every possible trust path, missing intermediates named, and the
    /// AIA URLs where they could be fetched from.
    /// </summary>
    [HttpPost("chain/analyze")]
    public ActionResult<object> AnalyzeChain(ChainAnalysisRequest req)
    {
        try { return ChainBuilder.Analyze(req.LeafPem, req.PoolPem); }
        catch (Exception ex) when (ex is ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }
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

/// <summary>
/// Stored artifact metadata and controlled download (design doc §5.1, §31). Content is
/// envelope-encrypted at rest; every read is audited, and key-bearing artifacts disappear
/// when their TTL expires.
/// </summary>
[ApiController]
[Route("api/v1/artifacts/stored")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "CertOps")]
public class StoredArtifactsController(
    IRemoteSslDbContext db, Application.Artifacts.ArtifactService artifacts) : ControllerBase
{
    [HttpGet]
    public async Task<IEnumerable<object>> List(
        [FromQuery] Guid? certificateVersionId, [FromQuery] Guid? deploymentJobId,
        [FromQuery] int take = 100, CancellationToken ct = default)
    {
        var q = db.Artifacts.AsNoTracking().OrderByDescending(a => a.CreatedAt).AsQueryable();
        if (certificateVersionId is not null) q = q.Where(a => a.CertificateVersionId == certificateVersionId);
        if (deploymentJobId is not null) q = q.Where(a => a.DeploymentJobId == deploymentJobId);

        return await q.Take(Math.Min(take, 500)).Select(a => new
        {
            a.Id, a.Kind, Sensitivity = a.Sensitivity.ToString(), a.FileName, a.ContentType,
            a.SizeBytes, a.Sha256, a.StorageProvider, a.CertificateId, a.CertificateVersionId,
            a.DeploymentJobId, a.ExpiresAt, a.CreatedBy, a.CreatedAt, a.PurgedAt, a.PurgeReason
        }).ToListAsync(ct);
    }

    [HttpGet("{id:guid}/download")]
    public async Task<IActionResult> Download(Guid id, CancellationToken ct)
    {
        try
        {
            var classification = await db.Artifacts.AsNoTracking()
                .Where(a => a.Id == id).Select(a => (ArtifactSensitivity?)a.Sensitivity).FirstOrDefaultAsync(ct);
            if (classification is null) return NotFound();
            // Key-bearing artifacts exist for the deployment pipeline, not for download (§7.3, §22.3).
            if (classification is ArtifactSensitivity.Sensitive or ArtifactSensitivity.HighlySensitive)
                return UnprocessableEntity(new ProblemDetails
                {
                    Title = "This artifact contains private key material and is never served over the API."
                });

            var (meta, content) = await artifacts.RetrieveAsync(id, User.Identity?.Name ?? "api", ct);
            return File(content, meta.ContentType, meta.FileName);
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    /// <summary>Securely deletes an artifact's content ahead of its TTL (§15.4).</summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Purge(Guid id, CancellationToken ct)
    {
        var artifact = await db.Artifacts.FirstOrDefaultAsync(a => a.Id == id, ct);
        if (artifact is null) return NotFound();
        await artifacts.PurgeAsync(artifact, "purged on request", ct);
        await db.SaveChangesAsync(ct);
        return NoContent();
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

    public record UpdateConnectorRequest(string? Name, JsonElement? Config, bool? Enabled);

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateConnectorRequest req, CancellationToken ct)
    {
        var c = await db.CaConnectors.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (c is null) return NotFound();
        if (!string.IsNullOrWhiteSpace(req.Name)) c.Name = req.Name;
        if (req.Config is not null) c.EncryptedConfigJson = protector.Protect(req.Config.Value.GetRawText());
        if (req.Enabled.HasValue) c.Enabled = req.Enabled.Value;
        audit.Append("user:api", "ca-connector.update", "ca_connector", id.ToString(), "OK", new { c.Name });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var c = await db.CaConnectors.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (c is null) return NotFound();
        if (await db.RenewalPolicies.AnyAsync(pp => pp.CaConnectorId == id, ct))
            return Conflict(new ProblemDetails { Title = "Connector is referenced by renewal policies." });
        db.CaConnectors.Remove(c);
        audit.Append("user:api", "ca-connector.delete", "ca_connector", id.ToString(), "OK");
        await db.SaveChangesAsync(ct);
        return NoContent();
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

    public record UpdatePolicyRequest(
        string? Name, int? TriggerDays, bool? RotateKey, bool? AutoDeploy, bool? ApprovalRequired,
        JsonElement? MaintenanceWindow, bool ClearMaintenanceWindow = false,
        Guid? CaConnectorId = null, bool? Enabled = null);

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdatePolicyRequest req, CancellationToken ct)
    {
        var p = await db.RenewalPolicies.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return NotFound();
        if (!string.IsNullOrWhiteSpace(req.Name)) p.Name = req.Name;
        if (req.TriggerDays.HasValue) p.TriggerDays = req.TriggerDays.Value;
        if (req.RotateKey.HasValue) p.RotateKey = req.RotateKey.Value;
        if (req.AutoDeploy.HasValue) p.AutoDeploy = req.AutoDeploy.Value;
        if (req.ApprovalRequired.HasValue) p.ApprovalRequired = req.ApprovalRequired.Value;
        if (req.Enabled.HasValue) p.Enabled = req.Enabled.Value;
        if (req.ClearMaintenanceWindow) p.MaintenanceWindowJson = null;
        else if (req.MaintenanceWindow is not null) p.MaintenanceWindowJson = req.MaintenanceWindow.Value.GetRawText();
        if (req.CaConnectorId is not null) p.CaConnectorId = req.CaConnectorId;
        audit.Append("user:api", "policy.update", "renewal_policy", id.ToString(), "OK", new { p.Name });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var p = await db.RenewalPolicies.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return NotFound();
        var assigned = await db.Certificates.Where(c => c.RenewalPolicyId == id).ToListAsync(ct);
        foreach (var c in assigned) c.RenewalPolicyId = null;
        db.RenewalPolicies.Remove(p);
        audit.Append("user:api", "policy.delete", "renewal_policy", id.ToString(), "OK", new { unassigned = assigned.Count });
        await db.SaveChangesAsync(ct);
        return NoContent();
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
public class AuditController(
    IRemoteSslDbContext db, RemoteSSL.Application.Auditing.AuditChain chain) : ControllerBase
{
    /// <summary>
    /// Audit search (design doc §43): every field an investigator filters on — who, what, which
    /// object, what outcome, and when. Results are newest first and paged with skip/take.
    /// </summary>
    [HttpGet]
    public async Task<object> List(
        [FromQuery] string? action, [FromQuery] string? actor, [FromQuery] string? objectType,
        [FromQuery] string? objectId, [FromQuery] string? result, [FromQuery] string? correlationId,
        [FromQuery] DateTimeOffset? from, [FromQuery] DateTimeOffset? to,
        [FromQuery] int skip = 0, [FromQuery] int take = 100, CancellationToken ct = default)
    {
        var q = db.AuditEvents.AsNoTracking().AsQueryable();
        if (!string.IsNullOrEmpty(action)) q = q.Where(e => e.Action.StartsWith(action));
        if (!string.IsNullOrEmpty(actor)) q = q.Where(e => e.Actor.Contains(actor));
        if (!string.IsNullOrEmpty(objectType)) q = q.Where(e => e.ObjectType == objectType);
        if (!string.IsNullOrEmpty(objectId)) q = q.Where(e => e.ObjectId == objectId);
        if (!string.IsNullOrEmpty(result)) q = q.Where(e => e.Result == result);
        if (!string.IsNullOrEmpty(correlationId)) q = q.Where(e => e.CorrelationId == correlationId);
        if (from is not null) q = q.Where(e => e.Timestamp >= from);
        if (to is not null) q = q.Where(e => e.Timestamp <= to);

        var total = await q.CountAsync(ct);
        var items = await q.OrderByDescending(e => e.Timestamp).ThenByDescending(e => e.Id)
            .Skip(Math.Max(0, skip)).Take(Math.Clamp(take, 1, 500))
            .Select(e => new
            {
                e.Id, e.Timestamp, e.Actor, e.Action, e.ObjectType, e.ObjectId, e.Result,
                e.CorrelationId, e.DetailsJson, e.SessionId, e.SourceIp, e.UserAgent,
                e.ApprovalReference, e.OldFingerprint, e.NewFingerprint,
                e.Sequence, Sealed = e.Hash != null, Archived = e.ArchivedAt != null
            })
            .ToListAsync(ct);

        return new { Total = total, Skip = skip, Items = items };
    }

    /// <summary>The distinct actions and object types present, so the search form can offer them.</summary>
    [HttpGet("facets")]
    public async Task<object> Facets(CancellationToken ct) => new
    {
        Actions = await db.AuditEvents.AsNoTracking().Select(e => e.Action).Distinct().OrderBy(a => a).ToListAsync(ct),
        ObjectTypes = await db.AuditEvents.AsNoTracking().Select(e => e.ObjectType).Distinct().OrderBy(o => o).ToListAsync(ct),
        Results = await db.AuditEvents.AsNoTracking().Select(e => e.Result).Distinct().OrderBy(r => r).ToListAsync(ct)
    };

    /// <summary>
    /// Walks the hash chain and reports whether the log still adds up (§25.3, ADR-007). This is
    /// the check an auditor runs; it reads every sealed row, so it is not a per-page call.
    /// </summary>
    [HttpGet("integrity")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Auditor")]
    public async Task<object> Integrity(CancellationToken ct)
    {
        var status = await chain.VerifyAsync(ct);
        var archived = await db.AuditEvents.CountAsync(e => e.ArchivedAt != null, ct);
        return new
        {
            status.Intact, status.Sealed, status.Unsealed, status.FirstBrokenSequence,
            status.Detail, status.HeadHash, Archived = archived
        };
    }

    /// <summary>
    /// The whole §32.2 chain behind one trace id: certificate request → CA → deployment
    /// job → runner jobs → target, joined with the audit trail and the latency samples
    /// recorded along the way.
    /// </summary>
    [HttpGet("trace/{correlationId}")]
    public async Task<object> Trace(string correlationId, CancellationToken ct)
    {
        var events = await db.AuditEvents.AsNoTracking()
            .Where(e => e.CorrelationId == correlationId)
            .OrderBy(e => e.Timestamp)
            .Select(e => new { e.Timestamp, e.Actor, e.Action, e.ObjectType, e.ObjectId, e.Result, e.DetailsJson })
            .ToListAsync(ct);

        var request = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.CorrelationId == correlationId)
            .Select(r => new { r.Id, r.CommonName, State = r.State.ToString(), r.CreatedAt, r.UpdatedAt, r.ErrorMessage })
            .FirstOrDefaultAsync(ct);

        var jobs = await db.DeploymentJobs.AsNoTracking()
            .Where(j => j.CorrelationId == correlationId)
            .Select(j => new
            {
                j.Id, Status = j.Status.ToString(), j.Strategy, j.RequestedBy,
                j.CreatedAt, j.StartedAt, j.CompletedAt,
                Certificate = j.CertificateVersion.Certificate.CommonName,
                TargetCount = j.Targets.Count
            })
            .ToListAsync(ct);

        var runnerJobs = await db.RunnerJobs.AsNoTracking()
            .Where(j => j.CorrelationId == correlationId)
            .OrderBy(j => j.CreatedAt)
            .Select(j => new { j.Id, j.JobType, j.Status, j.RunnerId, j.CreatedAt, j.ClaimedAt, j.CompletedAt })
            .ToListAsync(ct);

        var samples = await db.MetricSamples.AsNoTracking()
            .Where(s => s.CorrelationId == correlationId)
            .OrderBy(s => s.Timestamp)
            .Select(s => new { s.Timestamp, s.Metric, s.ValueMs, s.Label, s.Success })
            .ToListAsync(ct);

        return new { CorrelationId = correlationId, Request = request, DeploymentJobs = jobs, RunnerJobs = runnerJobs, Events = events, Metrics = samples };
    }
}
