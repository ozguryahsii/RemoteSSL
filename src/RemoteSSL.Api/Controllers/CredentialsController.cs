using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Security;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Credential references (design doc §7.2). Secret values are write-only: accepted on create or
/// rotation, never returned. What comes back is metadata only — type, provider, who touched it
/// last, and whether a rotation is due.
/// </summary>
[ApiController]
[Route("api/v1/credentials")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
public class CredentialsController(
    IRemoteSslDbContext db, ISecretProtector protector, AuditWriter audit, SecretBroker broker) : ControllerBase
{
    /// <summary>
    /// The secret half of a credential, in the shape §7.2 needs for every supported type. Which
    /// fields matter depends on <c>CredentialType</c>; the rest stay null.
    /// </summary>
    public record SecretInput(
        string? Password, string? PrivateKeyPem, string? SshCertificate, string? Realm,
        string? Token, string? ClientId, string? ClientSecret, string? TokenEndpoint,
        string? Pkcs12Base64, string? Pkcs12Password);

    public record CreateCredentialRequest(
        string Name, string CredentialType, string? Username,
        string? Provider, string? SecretIdentifier, int RotationIntervalDays,
        SecretInput? Secret,
        // Kept so existing callers and the simple username/password form keep working.
        string? Password, string? PrivateKeyPem);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct)
    {
        var credentials = await db.CredentialRefs.AsNoTracking().OrderBy(c => c.Name).ToListAsync(ct);
        return credentials.Select(c => new
        {
            c.Id,
            c.Name,
            CredentialType = c.CredentialType.ToString(),
            Provider = c.Provider.ToString(),
            c.Username,
            c.SecretIdentifier,
            HasSecret = c.EncryptedSecret != null,
            c.RotationIntervalDays,
            c.LastRotatedAt,
            c.RotationDueAt,
            RotationOverdue = c.RotationDueAt is not null && c.RotationDueAt <= DateTimeOffset.UtcNow,
            c.RotationPending,
            c.LastAccessedAt,
            c.LastAccessedBy,
            c.CreatedAt
        });
    }

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateCredentialRequest req, CancellationToken ct)
    {
        var provider = Enum.TryParse<SecretProviderType>(req.Provider, true, out var pv) ? pv : SecretProviderType.InternalVault;
        var credentialType = Enum.TryParse<CredentialType>(req.CredentialType, true, out var ctype)
            ? ctype : CredentialType.UsernamePassword;

        var material = Materialize(req.Secret, req.Password, req.PrivateKeyPem);
        string? encrypted = null;
        if (provider == SecretProviderType.InternalVault)
        {
            var problem = CredentialValidation.Validate(credentialType, material);
            if (problem is not null) return ValidationProblem(problem);
            encrypted = protector.Protect(Serialize(material));
        }
        else if (string.IsNullOrWhiteSpace(req.SecretIdentifier))
        {
            return ValidationProblem($"{provider} credentials need a secret identifier.");
        }

        var cred = new CredentialRef
        {
            Id = Guid.NewGuid(),
            Name = req.Name,
            CredentialType = credentialType,
            Provider = provider,
            Username = req.Username,
            SecretIdentifier = req.SecretIdentifier ?? $"internal://{req.Name}",
            EncryptedSecret = encrypted,
            RotationIntervalDays = Math.Max(0, req.RotationIntervalDays),
            LastRotatedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.CredentialRefs.Add(cred);
        audit.Append(Actor(), "credential.create", "credential_ref", cred.Id.ToString(), "OK",
            new { req.Name, Type = credentialType.ToString(), Provider = provider.ToString() });
        await db.SaveChangesAsync(ct);
        return new { cred.Id };
    }

    public record UpdateCredentialRequest(
        string? Name, string? Username, string? CredentialType, string? SecretIdentifier,
        int? RotationIntervalDays, SecretInput? Secret, string? Password, string? PrivateKeyPem);

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateCredentialRequest req, CancellationToken ct)
    {
        var cred = await db.CredentialRefs.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cred is null) return NotFound();

        if (!string.IsNullOrWhiteSpace(req.Name)) cred.Name = req.Name;
        if (req.Username is not null) cred.Username = req.Username;
        if (!string.IsNullOrWhiteSpace(req.SecretIdentifier)) cred.SecretIdentifier = req.SecretIdentifier;
        if (req.RotationIntervalDays is { } days) cred.RotationIntervalDays = Math.Max(0, days);
        if (Enum.TryParse<CredentialType>(req.CredentialType, true, out var ctype)) cred.CredentialType = ctype;

        var material = Materialize(req.Secret, req.Password, req.PrivateKeyPem);
        if (!IsEmpty(material))
        {
            if (cred.Provider != SecretProviderType.InternalVault)
                return ValidationProblem($"{cred.Provider} credentials hold their secret in the provider, not here.");
            var problem = CredentialValidation.Validate(cred.CredentialType, material);
            if (problem is not null) return ValidationProblem(problem);
            cred.EncryptedSecret = protector.Protect(Serialize(material));
            cred.LastRotatedAt = DateTimeOffset.UtcNow;
            cred.RotationPending = false;
        }

        cred.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append(Actor(), "credential.update", "credential_ref", id.ToString(), "OK", new { cred.Name });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    public record RotateRequest(SecretInput? Secret, string? Password, string? PrivateKeyPem);

    /// <summary>Rotation (§7.3): new material for internal credentials, clock reset for external ones.</summary>
    [HttpPost("{id:guid}/rotate")]
    public async Task<IActionResult> Rotate(Guid id, RotateRequest req, CancellationToken ct)
    {
        var material = Materialize(req.Secret, req.Password, req.PrivateKeyPem);
        try
        {
            await broker.RotateAsync(id, IsEmpty(material) ? null : material, Actor(), ct);
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (ArgumentException ex) { return ValidationProblem(ex.Message); }
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var cred = await db.CredentialRefs.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cred is null) return NotFound();
        if (await db.Targets.AnyAsync(t => t.CredentialRefId == id, ct))
            return Conflict(new ProblemDetails { Title = "Credential is referenced by targets" });
        db.CredentialRefs.Remove(cred);
        audit.Append(Actor(), "credential.delete", "credential_ref", id.ToString(), "OK");
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private string Actor() => User.Identity?.Name is { Length: > 0 } name ? $"user:{name}" : "user:api";

    private static SecretMaterial Materialize(SecretInput? input, string? password, string? privateKeyPem) =>
        new(
            Password: input?.Password ?? password,
            PrivateKeyPem: input?.PrivateKeyPem ?? privateKeyPem,
            SshCertificate: input?.SshCertificate,
            Realm: input?.Realm,
            Token: input?.Token,
            ClientId: input?.ClientId,
            ClientSecret: input?.ClientSecret,
            TokenEndpoint: input?.TokenEndpoint,
            Pkcs12Base64: input?.Pkcs12Base64,
            Pkcs12Password: input?.Pkcs12Password);

    private static bool IsEmpty(SecretMaterial m) =>
        string.IsNullOrEmpty(m.Password) && string.IsNullOrEmpty(m.PrivateKeyPem)
        && string.IsNullOrEmpty(m.SshCertificate) && string.IsNullOrEmpty(m.Token)
        && string.IsNullOrEmpty(m.ClientSecret) && string.IsNullOrEmpty(m.Pkcs12Base64);

    private static string Serialize(SecretMaterial material) =>
        JsonSerializer.Serialize(material, new JsonSerializerOptions(JsonSerializerDefaults.Web));

}
