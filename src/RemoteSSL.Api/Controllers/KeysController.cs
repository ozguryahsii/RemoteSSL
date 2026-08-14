using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Security;
using RemoteSSL.Domain;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Managed private keys (design doc §16.3): software, PKCS#11 token or cloud HSM. The private
/// half is never returned unless the key was explicitly created exportable, and every attempt is
/// audited either way.
/// </summary>
[ApiController]
[Route("api/v1/keys")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "CertOps")]
public class KeysController(IRemoteSslDbContext db, ManagedKeyService keys) : ControllerBase
{
    public record CreateKeyRequest(
        string Label, string? Provider, string? Algorithm, int? SizeOrCurve, bool Exportable,
        string? OwnerId, string? OwnerTeam, string? Environment, string? Purpose);

    public record CsrRequest(string Subject, string[]? Sans);

    /// <summary>Which key providers this deployment can actually use, for the create form.</summary>
    [HttpGet("providers")]
    public IEnumerable<object> Providers() => keys.AvailableProviders();

    [HttpGet]
    public async Task<IEnumerable<object>> List(bool includeDestroyed, CancellationToken ct) =>
        await db.ManagedKeys.AsNoTracking()
            .Where(k => includeDestroyed || k.DestroyedAt == null)
            .OrderByDescending(k => k.CreatedAt)
            .Select(k => new
            {
                k.Id, k.Label, Provider = k.Provider.ToString(), k.Reference, k.Algorithm, k.SizeOrCurve,
                k.Exportable, k.OwnerId, k.OwnerTeam, k.Environment, k.Purpose,
                k.CreatedBy, k.CreatedAt, k.LastUsedAt, k.DestroyedAt
            })
            .ToListAsync(ct);

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<object>> Get(Guid id, CancellationToken ct)
    {
        var key = await db.ManagedKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == id, ct);
        if (key is null) return NotFound();
        return new
        {
            key.Id, key.Label, Provider = key.Provider.ToString(), key.Reference, key.Algorithm,
            key.SizeOrCurve, key.PublicKeyPem, key.Exportable, key.OwnerId, key.OwnerTeam,
            key.Environment, key.Purpose, key.CreatedBy, key.CreatedAt, key.LastUsedAt, key.DestroyedAt
        };
    }

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateKeyRequest req, CancellationToken ct)
    {
        var provider = Enum.TryParse<KeyProviderKind>(req.Provider, true, out var kind) ? kind : KeyProviderKind.Software;
        try
        {
            var key = await keys.CreateAsync(new ManagedKeyService.CreateKeyInput(
                req.Label, provider, req.Algorithm ?? "RSA", req.SizeOrCurve ?? 3072, req.Exportable,
                req.OwnerId, req.OwnerTeam, req.Environment, req.Purpose), Actor(), ct);
            return new { key.Id, key.Reference, key.PublicKeyPem, key.Exportable };
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException)
        {
            return ValidationProblem(ex.Message);
        }
    }

    /// <summary>A CSR for this key; for token-backed keys the token performs the signature.</summary>
    [HttpPost("{id:guid}/csr")]
    public async Task<ActionResult<object>> Csr(Guid id, CsrRequest req, CancellationToken ct)
    {
        try
        {
            var csr = await keys.CreateCsrAsync(id, req.Subject, req.Sans ?? [], Actor(), ct);
            return new { CsrPem = csr };
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return ValidationProblem(ex.Message);
        }
    }

    [HttpPost("{id:guid}/export")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
    public async Task<ActionResult<object>> Export(Guid id, CancellationToken ct)
    {
        try
        {
            return new { PrivateKeyPem = await keys.ExportPrivateKeyAsync(id, Actor(), ct) };
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (KeyExportDeniedException ex)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new ProblemDetails { Title = ex.Message });
        }
    }

    [HttpDelete("{id:guid}")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        try
        {
            await keys.DestroyAsync(id, Actor(), ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return ValidationProblem(ex.Message); }
    }

    private string Actor() => User.Identity?.Name is { Length: > 0 } name ? $"user:{name}" : "user:api";
}
