using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Security;

/// <summary>Raised when a key's export policy forbids what the caller asked for (§16.3).</summary>
public class KeyExportDeniedException(string message) : Exception(message);

/// <summary>
/// Key lifecycle across all providers (design doc §16.3): creation with an owner and an export
/// policy, CSR generation that never moves the private half, export that is refused unless the
/// policy allows it, and destruction. Every one of those is audited.
/// </summary>
public class ManagedKeyService(
    IRemoteSslDbContext db, ISecretProtector protector, AuditWriter audit, IEnumerable<IKeyProvider> providers)
{
    public sealed record CreateKeyInput(
        string Label, KeyProviderKind Provider, string Algorithm, int SizeOrCurve, bool Exportable,
        string? OwnerId, string? OwnerTeam, string? Environment, string? Purpose);

    /// <summary>Providers that are actually usable in this deployment, for the UI to offer.</summary>
    public IEnumerable<object> AvailableProviders() =>
        providers.Select(p => new { Provider = p.Kind.ToString(), p.Enabled });

    public async Task<ManagedKey> CreateAsync(CreateKeyInput input, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(input.Label))
            throw new ArgumentException("A key needs a label.");
        if (await db.ManagedKeys.AnyAsync(k => k.Label == input.Label && k.DestroyedAt == null, ct))
            throw new InvalidOperationException($"A live key labelled '{input.Label}' already exists.");

        var provider = Resolve(input.Provider);
        var generated = await provider.GenerateAsync(
            new KeySpec(input.Algorithm, input.SizeOrCurve, input.Label, input.Exportable), ct);

        var key = new ManagedKey
        {
            Id = Guid.NewGuid(),
            Label = input.Label,
            Provider = input.Provider,
            Reference = generated.Reference,
            Algorithm = input.Algorithm,
            SizeOrCurve = input.SizeOrCurve,
            PublicKeyPem = generated.PublicKeyPem,
            EncryptedPrivateKeyPem = generated.PrivateKeyPem is null ? null : protector.Protect(generated.PrivateKeyPem),
            // Only a software key can even physically be exported; the token providers refuse the
            // request earlier, so this can never overstate what the platform is able to do.
            Exportable = input.Exportable && input.Provider == KeyProviderKind.Software,
            OwnerId = input.OwnerId,
            OwnerTeam = input.OwnerTeam,
            Environment = input.Environment,
            Purpose = input.Purpose,
            CreatedBy = actor,
            CreatedAt = DateTimeOffset.UtcNow
        };

        db.ManagedKeys.Add(key);
        audit.Append(actor, "key.create", "managed_key", key.Id.ToString(), "OK",
            new { key.Label, Provider = key.Provider.ToString(), key.Algorithm, key.SizeOrCurve, key.Exportable, key.OwnerId });
        await db.SaveChangesAsync(ct);
        return key;
    }

    /// <summary>Produces a CSR for the key. Token-backed keys sign on the token.</summary>
    public async Task<string> CreateCsrAsync(Guid id, string subject, IReadOnlyList<string> sans,
        string actor, CancellationToken ct)
    {
        var key = await LoadAsync(id, ct);
        var provider = Resolve(key.Provider);
        var privateKeyPem = key.EncryptedPrivateKeyPem is null ? null : protector.Unprotect(key.EncryptedPrivateKeyPem);

        var csr = await provider.CreateCsrPemAsync(key.Reference, subject, sans, privateKeyPem, ct);
        key.LastUsedAt = DateTimeOffset.UtcNow;
        audit.Append(actor, "key.csr", "managed_key", key.Id.ToString(), "OK", new { key.Label, subject });
        await db.SaveChangesAsync(ct);
        return csr;
    }

    /// <summary>
    /// Hands out the private key — only when the export policy allows it. The refusal is audited
    /// too, because an attempt to export a protected key is exactly what an operator wants to see.
    /// </summary>
    public async Task<string> ExportPrivateKeyAsync(Guid id, string actor, CancellationToken ct)
    {
        var key = await LoadAsync(id, ct);
        if (!key.Exportable || key.EncryptedPrivateKeyPem is null)
        {
            audit.Append(actor, "key.export", "managed_key", key.Id.ToString(), "DENIED",
                new { key.Label, Provider = key.Provider.ToString(), reason = "export policy" });
            await db.SaveChangesAsync(ct);
            throw new KeyExportDeniedException(
                $"Key '{key.Label}' was created non-exportable; its private half cannot be retrieved.");
        }

        audit.Append(actor, "key.export", "managed_key", key.Id.ToString(), "OK", new { key.Label });
        await db.SaveChangesAsync(ct);
        return protector.Unprotect(key.EncryptedPrivateKeyPem);
    }

    public async Task DestroyAsync(Guid id, string actor, CancellationToken ct)
    {
        var key = await LoadAsync(id, ct);
        await Resolve(key.Provider).DestroyAsync(key.Reference, ct);
        key.EncryptedPrivateKeyPem = null;
        key.DestroyedAt = DateTimeOffset.UtcNow;
        audit.Append(actor, "key.destroy", "managed_key", key.Id.ToString(), "OK", new { key.Label });
        await db.SaveChangesAsync(ct);
    }

    private async Task<ManagedKey> LoadAsync(Guid id, CancellationToken ct) =>
        await db.ManagedKeys.FirstOrDefaultAsync(k => k.Id == id && k.DestroyedAt == null, ct)
        ?? throw new KeyNotFoundException("Key not found");

    private IKeyProvider Resolve(KeyProviderKind kind)
    {
        var provider = providers.FirstOrDefault(p => p.Kind == kind)
                       ?? throw new InvalidOperationException($"Key provider '{kind}' has no implementation registered.");
        if (!provider.Enabled)
            throw new InvalidOperationException($"Key provider '{kind}' is not configured in this deployment.");
        return provider;
    }
}
