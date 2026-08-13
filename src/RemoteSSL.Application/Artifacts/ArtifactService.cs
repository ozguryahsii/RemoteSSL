using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Artifacts;

/// <summary>Where artifact ciphertext lives. The database provider is always available.</summary>
public interface IArtifactObjectStore
{
    string Provider { get; }
    /// <summary>False when the provider is registered but not configured; it is then never chosen.</summary>
    bool Enabled { get; }
    Task PutAsync(string key, byte[] ciphertext, CancellationToken ct);
    Task<byte[]> GetAsync(string key, CancellationToken ct);
    Task DeleteAsync(string key, CancellationToken ct);
}

/// <summary>
/// Stores and retrieves deployment artifacts under the rules of design doc §31: envelope
/// encryption, sensitivity classes, TTL on key-bearing material, secure deletion and an
/// access record for every read (§15.4).
/// </summary>
public class ArtifactService(
    IRemoteSslDbContext db, ISecretProtector protector, AuditWriter audit,
    IEnumerable<IArtifactObjectStore> stores, IConfiguration configuration)
{
    /// <summary>Default lifetime for artifacts that contain private key material (§31.1).</summary>
    public static readonly TimeSpan DefaultSensitiveTtl = TimeSpan.FromHours(24);

    public async Task<Artifact> StoreAsync(
        string kind, ArtifactSensitivity sensitivity, string fileName, string contentType,
        byte[] content, string? createdBy, CancellationToken ct,
        Guid? certificateId = null, Guid? certificateVersionId = null,
        Guid? deploymentJobId = null, Guid? targetId = null, TimeSpan? ttl = null,
        string? preferredProvider = null)
    {
        var sealedArtifact = EnvelopeCipher.Seal(content);
        var store = ResolveStore(preferredProvider);
        var id = Guid.NewGuid();
        var storageRef = $"artifacts/{DateTimeOffset.UtcNow:yyyy/MM/dd}/{id:N}";

        var artifact = new Artifact
        {
            Id = id,
            Kind = kind,
            Sensitivity = sensitivity,
            CertificateId = certificateId,
            CertificateVersionId = certificateVersionId,
            DeploymentJobId = deploymentJobId,
            TargetId = targetId,
            FileName = fileName,
            ContentType = contentType,
            SizeBytes = content.LongLength,
            Sha256 = sealedArtifact.Sha256,
            StorageProvider = store?.Provider ?? "database",
            StorageRef = storageRef,
            Nonce = sealedArtifact.Nonce,
            Tag = sealedArtifact.Tag,
            // The data key is wrapped by the key-encryption key; only the wrapped form is persisted.
            WrappedDataKey = protector.Protect(Convert.ToBase64String(sealedArtifact.DataKey)),
            // Key-bearing artifacts always get a lifetime, whether or not the caller asked (§5.3).
            ExpiresAt = ResolveExpiry(sensitivity, ttl),
            CreatedBy = createdBy,
            CreatedAt = DateTimeOffset.UtcNow
        };

        if (store is null) artifact.Ciphertext = sealedArtifact.Ciphertext;
        else await store.PutAsync(storageRef, sealedArtifact.Ciphertext, ct);

        db.Artifacts.Add(artifact);
        audit.Append(createdBy is null ? "service:artifacts" : $"user:{createdBy}", "artifact.store",
            "artifact", artifact.Id.ToString(), "OK",
            new
            {
                artifact.Kind, Sensitivity = sensitivity.ToString(), artifact.FileName,
                artifact.SizeBytes, artifact.StorageProvider, artifact.ExpiresAt
            });
        await db.SaveChangesAsync(ct);
        return artifact;
    }

    /// <summary>
    /// Records an artifact that lives outside RemoteSSL — a backup the adapter left on the
    /// target (§31.1). There is no ciphertext to store: the value is knowing it exists, where,
    /// and when its retention window passes.
    /// </summary>
    public Artifact RecordExternal(
        string kind, ArtifactSensitivity sensitivity, string location, string? createdBy,
        Guid? deploymentJobId = null, Guid? targetId = null, Guid? certificateVersionId = null,
        TimeSpan? retention = null)
    {
        var artifact = new Artifact
        {
            Id = Guid.NewGuid(),
            Kind = kind,
            Sensitivity = sensitivity,
            DeploymentJobId = deploymentJobId,
            TargetId = targetId,
            CertificateVersionId = certificateVersionId,
            FileName = location,
            ContentType = "application/octet-stream",
            StorageProvider = "target",
            StorageRef = location,
            ExpiresAt = retention is null ? null : DateTimeOffset.UtcNow.Add(retention.Value),
            CreatedBy = createdBy,
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.Artifacts.Add(artifact);
        return artifact;
    }

    /// <summary>
    /// Returns the plaintext and records the access (§15.4). Purged or expired artifacts are
    /// refused rather than silently returning nothing.
    /// </summary>
    public async Task<(Artifact Meta, byte[] Content)> RetrieveAsync(Guid id, string? actor, CancellationToken ct)
    {
        var artifact = await db.Artifacts.FirstOrDefaultAsync(a => a.Id == id, ct)
                       ?? throw new KeyNotFoundException("Artifact not found");
        if (artifact.PurgedAt is not null)
            throw new InvalidOperationException($"Artifact was purged on {artifact.PurgedAt:u} ({artifact.PurgeReason}).");
        if (artifact.ExpiresAt is { } exp && exp <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Artifact has expired and is awaiting secure deletion.");

        if (artifact.StorageProvider == "target")
            throw new InvalidOperationException(
                $"This artifact is a backup kept on the target itself ({artifact.StorageRef}); "
                + "RemoteSSL holds only its metadata.");

        var ciphertext = artifact.StorageProvider == "database"
            ? artifact.Ciphertext ?? throw new InvalidOperationException("Artifact content is missing.")
            : await ResolveStore(artifact.StorageProvider)!.GetAsync(artifact.StorageRef, ct);

        var dataKey = Convert.FromBase64String(protector.Unprotect(artifact.WrappedDataKey));
        var content = EnvelopeCipher.Open(ciphertext, artifact.Nonce, artifact.Tag, dataKey);

        if (Convert.ToHexString(SHA256.HashData(content)) != artifact.Sha256)
            throw new InvalidOperationException("Artifact integrity check failed: content hash does not match.");

        audit.Append(actor is null ? "service:artifacts" : $"user:{actor}", "artifact.access",
            "artifact", artifact.Id.ToString(), "OK",
            new { artifact.Kind, Sensitivity = artifact.Sensitivity.ToString(), artifact.FileName });
        await db.SaveChangesAsync(ct);
        return (artifact, content);
    }

    /// <summary>
    /// Secure deletion (§15.4): the ciphertext is destroyed and the data key wrapper cleared,
    /// so the content cannot be recovered even with database access. The metadata row remains
    /// as evidence that the artifact existed and when it went.
    /// </summary>
    public async Task PurgeAsync(Artifact artifact, string reason, CancellationToken ct)
    {
        if (artifact.PurgedAt is not null) return;

        if (artifact.StorageProvider != "database")
        {
            var store = ResolveStore(artifact.StorageProvider);
            if (store is not null) await store.DeleteAsync(artifact.StorageRef, ct);
        }

        artifact.Ciphertext = null;
        artifact.WrappedDataKey = string.Empty;
        artifact.Nonce = [];
        artifact.Tag = [];
        artifact.PurgedAt = DateTimeOffset.UtcNow;
        artifact.PurgeReason = reason;

        audit.Append("service:artifacts", "artifact.purge", "artifact", artifact.Id.ToString(), "PURGED",
            new { artifact.Kind, Sensitivity = artifact.Sensitivity.ToString(), reason });
    }

    /// <summary>Key-bearing artifacts must not outlive their purpose; a caller cannot opt out.</summary>
    private static DateTimeOffset? ResolveExpiry(ArtifactSensitivity sensitivity, TimeSpan? ttl) =>
        sensitivity switch
        {
            ArtifactSensitivity.Sensitive or ArtifactSensitivity.HighlySensitive =>
                DateTimeOffset.UtcNow.Add(ttl ?? DefaultSensitiveTtl),
            _ => ttl is null ? null : DateTimeOffset.UtcNow.Add(ttl.Value)
        };

    /// <summary>
    /// Null means "keep the ciphertext in the database". A configured provider is only used
    /// when it reports itself as enabled, so a half-configured bucket cannot swallow artifacts.
    /// </summary>
    private IArtifactObjectStore? ResolveStore(string? provider)
    {
        provider ??= configuration["Storage:ArtifactProvider"] ?? "database";
        if (provider == "database") return null;

        var store = stores.FirstOrDefault(s => s.Provider == provider)
                    ?? throw new InvalidOperationException($"Artifact storage provider '{provider}' is unknown.");
        if (!store.Enabled)
            throw new InvalidOperationException(
                $"Artifact storage provider '{provider}' is selected but not configured.");
        return store;
    }
}
