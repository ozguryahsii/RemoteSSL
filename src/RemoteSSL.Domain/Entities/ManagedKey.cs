namespace RemoteSSL.Domain.Entities;

/// <summary>
/// A private key the platform is responsible for (design doc §16.3). The row is the key's
/// identity card — where it lives, whether it may ever leave, and who owns it. For software keys
/// it also carries the encrypted key itself; for token-backed keys it carries only a reference,
/// because the private half cannot be read out of the token at all.
/// </summary>
public class ManagedKey : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35); every query is filtered to it. Left empty on construction
    /// and stamped at save time from the tenant in force, so a row cannot be created under the
    /// wrong tenant by forgetting to set it.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public string Label { get; set; } = string.Empty;
    public KeyProviderKind Provider { get; set; }

    /// <summary>
    /// Provider-specific locator: "software://&lt;id&gt;", "pkcs11://&lt;token&gt;/&lt;label&gt;",
    /// or a cloud KMS key URI.
    /// </summary>
    public string Reference { get; set; } = string.Empty;

    public string Algorithm { get; set; } = "RSA";
    public int SizeOrCurve { get; set; } = 3072;
    public string PublicKeyPem { get; set; } = string.Empty;

    /// <summary>Data-protection-encrypted private key; only ever set for software keys.</summary>
    public string? EncryptedPrivateKeyPem { get; set; }

    /// <summary>
    /// Export policy: false means no API path may ever hand out the private half. Once a key is
    /// created non-exportable this is not relaxed — that would make the original promise a lie.
    /// </summary>
    public bool Exportable { get; set; }

    // Ownership metadata (§16.3): a key without an accountable owner cannot be governed.
    public string? OwnerId { get; set; }
    public string? OwnerTeam { get; set; }
    public string? Environment { get; set; }
    public string? Purpose { get; set; }

    public string CreatedBy { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    /// <summary>Set when the key has been destroyed; the row survives for audit.</summary>
    public DateTimeOffset? DestroyedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
}
