using RemoteSSL.Domain;

namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Metadata for a stored artifact (design doc §5.1, §31). The bytes never live in this row:
/// they are envelope-encrypted and held by a storage provider, and only the reference and
/// hash are kept here (§31.2). Sensitivity drives retention and access rules — a public leaf
/// and a PFX carrying a private key are not the same class of object (§15.4).
/// </summary>
public class Artifact : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35). Carried on the child as well as the parent: a query that
    /// starts at the child would otherwise cross the tenant boundary the parent's filter draws.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }

    /// <summary>"csr" | "leaf" | "chain" | "fullchain" | "pfx" | "jks" | "key" | "backup".</summary>
    public string Kind { get; set; } = string.Empty;
    public ArtifactSensitivity Sensitivity { get; set; }

    public Guid? CertificateId { get; set; }
    public Guid? CertificateVersionId { get; set; }
    public Guid? DeploymentJobId { get; set; }
    public Guid? TargetId { get; set; }

    public string FileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long SizeBytes { get; set; }
    /// <summary>SHA-256 of the plaintext content, for integrity checks after retrieval.</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>"database" | "s3" — where the ciphertext lives.</summary>
    public string StorageProvider { get; set; } = "database";
    /// <summary>Object key/identifier inside the provider.</summary>
    public string StorageRef { get; set; } = string.Empty;

    /// <summary>Ciphertext, when the provider is the database. Null for external storage.</summary>
    public byte[]? Ciphertext { get; set; }
    /// <summary>AES-GCM nonce for this artifact's data key.</summary>
    public byte[] Nonce { get; set; } = [];
    /// <summary>AES-GCM authentication tag.</summary>
    public byte[] Tag { get; set; } = [];
    /// <summary>Per-artifact data key, itself encrypted with the key-encryption key (§31.2).</summary>
    public string WrappedDataKey { get; set; } = string.Empty;

    /// <summary>Mandatory for key-bearing artifacts (§5.3, §15.4); null = keep until deleted.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Set when the content was securely deleted; the row stays as an audit record.</summary>
    public DateTimeOffset? PurgedAt { get; set; }
    public string? PurgeReason { get; set; }
}
