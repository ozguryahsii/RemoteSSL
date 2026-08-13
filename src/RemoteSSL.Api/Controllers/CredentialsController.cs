using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>Credential references. Secret values are write-only: accepted on create, never returned.</summary>
[ApiController]
[Route("api/v1/credentials")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
public class CredentialsController(IRemoteSslDbContext db, ISecretProtector protector, AuditWriter audit) : ControllerBase
{
    public record CreateCredentialRequest(
        string Name, string CredentialType, string? Username,
        string? Password, string? PrivateKeyPem,
        string? Provider, string? SecretIdentifier);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.CredentialRefs.AsNoTracking().Select(c => new
        {
            c.Id, c.Name, CredentialType = c.CredentialType.ToString(),
            Provider = c.Provider.ToString(), c.Username,
            HasSecret = c.EncryptedSecret != null, c.CreatedAt
        }).ToListAsync(ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateCredentialRequest req, CancellationToken ct)
    {
        var provider = Enum.TryParse<SecretProviderType>(req.Provider, true, out var pv) ? pv : SecretProviderType.InternalVault;
        string? encrypted = null;
        if (provider == SecretProviderType.InternalVault)
        {
            if (string.IsNullOrEmpty(req.Password) && string.IsNullOrEmpty(req.PrivateKeyPem))
                return ValidationProblem("Internal vault credentials need a password or private key.");
            encrypted = protector.Protect(JsonSerializer.Serialize(new { req.Password, req.PrivateKeyPem }));
        }

        var cred = new CredentialRef
        {
            Id = Guid.NewGuid(),
            Name = req.Name,
            CredentialType = Enum.TryParse<CredentialType>(req.CredentialType, true, out var ctype)
                ? ctype : CredentialType.UsernamePassword,
            Provider = provider,
            Username = req.Username,
            SecretIdentifier = req.SecretIdentifier ?? $"internal://{req.Name}",
            EncryptedSecret = encrypted,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.CredentialRefs.Add(cred);
        audit.Append("user:api", "credential.create", "credential_ref", cred.Id.ToString(), "OK",
            new { req.Name, req.CredentialType });
        await db.SaveChangesAsync(ct);
        return new { cred.Id };
    }

    public record UpdateCredentialRequest(string? Name, string? Username, string? Password, string? PrivateKeyPem);

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateCredentialRequest req, CancellationToken ct)
    {
        var cred = await db.CredentialRefs.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cred is null) return NotFound();
        if (!string.IsNullOrWhiteSpace(req.Name)) cred.Name = req.Name;
        if (req.Username is not null) cred.Username = req.Username;
        if (!string.IsNullOrEmpty(req.Password) || !string.IsNullOrEmpty(req.PrivateKeyPem))
        {
            cred.EncryptedSecret = protector.Protect(JsonSerializer.Serialize(new { req.Password, req.PrivateKeyPem }));
            cred.CredentialType = !string.IsNullOrEmpty(req.PrivateKeyPem)
                ? Domain.CredentialType.SshPrivateKey : Domain.CredentialType.UsernamePassword;
        }
        cred.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append("user:api", "credential.update", "credential_ref", id.ToString(), "OK", new { cred.Name });
        await db.SaveChangesAsync(ct);
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
        audit.Append("user:api", "credential.delete", "credential_ref", id.ToString(), "OK");
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}
