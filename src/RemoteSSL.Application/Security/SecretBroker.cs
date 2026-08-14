using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Security;

/// <summary>
/// How a credential should reach the runner. "Value" means the control plane resolved the
/// secret; "Reference" means the runner fetches it itself from the provider (ADR-003
/// runner-direct), so the plaintext never passes through the control plane at all.
/// </summary>
public sealed record ResolvedCredential(
    string Mode,
    SecretMaterial? Material,
    SecretProviderType Provider,
    string? SecretIdentifier,
    CredentialType CredentialType,
    string? Username);

/// <summary>
/// The secret broker of design doc §4.2/§7.3: one place that decides where a credential comes
/// from, records every access, and keeps plaintext out of the control plane whenever the
/// deployment is configured for runner-direct retrieval.
/// </summary>
public class SecretBroker(
    IRemoteSslDbContext db, ISecretProtector protector, AuditWriter audit,
    IEnumerable<ISecretProvider> providers, Microsoft.Extensions.Configuration.IConfiguration configuration)
{
    /// <summary>
    /// Resolves a credential for a runner. External providers can be handed over as a
    /// reference when Secrets:RunnerDirect is on and the runner is configured for that
    /// provider — the control plane then never sees the secret (§7.3).
    /// </summary>
    public async Task<ResolvedCredential> ResolveForRunnerAsync(
        Guid credentialId, string actor, CancellationToken ct)
    {
        var credential = await db.CredentialRefs.FirstOrDefaultAsync(c => c.Id == credentialId, ct)
                         ?? throw new KeyNotFoundException("Credential not found");

        var runnerDirect = string.Equals(configuration["Secrets:RunnerDirect"], "true",
            StringComparison.OrdinalIgnoreCase);
        if (runnerDirect && credential.Provider != SecretProviderType.InternalVault)
        {
            RecordAccess(credential, actor, "reference");
            await db.SaveChangesAsync(ct);
            return new ResolvedCredential("Reference", null, credential.Provider,
                credential.SecretIdentifier, credential.CredentialType, credential.Username);
        }

        var material = await ReadAsync(credential, ct);
        RecordAccess(credential, actor, "value");
        await db.SaveChangesAsync(ct);

        return new ResolvedCredential("Value", material, credential.Provider,
            credential.SecretIdentifier, credential.CredentialType, credential.Username);
    }

    /// <summary>
    /// Replaces the secret material of an internally stored credential and restarts its rotation
    /// clock (§7.3). External providers rotate in the provider itself, so there only the clock is
    /// acknowledged — the identifier keeps pointing at whatever the provider now holds.
    /// </summary>
    public async Task RotateAsync(Guid credentialId, SecretMaterial? material, string actor, CancellationToken ct)
    {
        var credential = await db.CredentialRefs.FirstOrDefaultAsync(c => c.Id == credentialId, ct)
                         ?? throw new KeyNotFoundException("Credential not found");

        if (credential.Provider == SecretProviderType.InternalVault)
        {
            if (material is null)
                throw new ArgumentException("Rotating an internally stored credential needs new secret material.");
            credential.EncryptedSecret = protector.Protect(
                JsonSerializer.Serialize(material, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        }

        credential.LastRotatedAt = DateTimeOffset.UtcNow;
        credential.RotationPending = false;
        credential.UpdatedAt = DateTimeOffset.UtcNow;

        audit.Append(actor, "credential.rotate", "credential_ref", credential.Id.ToString(), "OK",
            new { credential.Name, Provider = credential.Provider.ToString() });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Credentials whose rotation cadence has elapsed. Marking them pending is deliberately not a
    /// block: a stale credential still works, it just becomes visible and alertable (§7.3).
    /// </summary>
    public async Task<IReadOnlyList<CredentialRef>> MarkOverdueRotationsAsync(
        DateTimeOffset now, CancellationToken ct)
    {
        var candidates = await db.CredentialRefs
            .Where(c => c.RotationIntervalDays > 0)
            .ToListAsync(ct);

        var overdue = candidates.Where(c => c.RotationDueAt is not null && c.RotationDueAt <= now).ToList();
        foreach (var credential in overdue.Where(c => !c.RotationPending))
        {
            credential.RotationPending = true;
            audit.Append("system", "credential.rotation_due", "credential_ref", credential.Id.ToString(), "OK",
                new { credential.Name, DueAt = credential.RotationDueAt });
        }

        if (overdue.Count > 0) await db.SaveChangesAsync(ct);
        return overdue;
    }

    /// <summary>Reads the secret material behind a credential, whatever provider holds it.</summary>
    public async Task<SecretMaterial> ReadAsync(CredentialRef credential, CancellationToken ct)
    {
        if (credential.Provider == SecretProviderType.InternalVault)
        {
            if (credential.EncryptedSecret is null) return new SecretMaterial();
            var json = protector.Unprotect(credential.EncryptedSecret);
            return JsonSerializer.Deserialize<SecretMaterial>(json,
                       new JsonSerializerOptions(JsonSerializerDefaults.Web))
                   ?? new SecretMaterial();
        }

        var provider = providers.FirstOrDefault(p => p.Provider == credential.Provider)
                       ?? throw new InvalidOperationException(
                           $"Secret provider '{credential.Provider}' has no implementation registered.");
        if (!provider.Enabled)
            throw new InvalidOperationException(
                $"Secret provider '{credential.Provider}' is referenced by '{credential.Name}' but is not configured.");

        return await provider.ReadAsync(credential.SecretIdentifier, ct);
    }

    /// <summary>
    /// Every read of a credential is recorded (§7.3 "secrets için rotation ve access audit
    /// desteklenmelidir"). The value never appears — only who asked, for what, and how.
    /// </summary>
    private void RecordAccess(CredentialRef credential, string actor, string mode)
    {
        credential.LastAccessedAt = DateTimeOffset.UtcNow;
        credential.LastAccessedBy = actor;
        audit.Append(actor, "credential.access", "credential_ref", credential.Id.ToString(), "OK",
            new
            {
                credential.Name,
                Provider = credential.Provider.ToString(),
                Type = credential.CredentialType.ToString(),
                mode
            });
    }
}
