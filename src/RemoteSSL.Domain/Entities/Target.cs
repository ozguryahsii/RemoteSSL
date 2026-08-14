namespace RemoteSSL.Domain.Entities;

/// <summary>
/// A managed deployment target (Linux/Windows server, network device, application).
/// Unlike a MonitorEndpoint, a Target carries a connection method, an adapter type and
/// a credential reference, and therefore supports install/activate/rollback actions.
/// </summary>
public class Target : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35); every query is filtered to it. Left empty on construction
    /// and stamped at save time from the tenant in force, so a row cannot be created under the
    /// wrong tenant by forgetting to set it.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public TargetType TargetType { get; set; }
    public string? OsType { get; set; }
    public string? Environment { get; set; }

    /// <summary>Adapter identifier, e.g. "nginx", "iis", "java-keystore", "f5-bigip".</summary>
    public string AdapterType { get; set; } = string.Empty;

    /// <summary>Adapter/vendor-specific connection settings as JSON (host, port, sudo policy…). Never secrets.</summary>
    public string ConnectionConfigJson { get; set; } = "{}";

    public Guid? CredentialRefId { get; set; }
    public CredentialRef? CredentialRef { get; set; }

    public Guid? RunnerId { get; set; }

    /// <summary>Group used by scope rules and bulk operations (§24.2 scope.targetGroup).</summary>
    public string? TargetGroup { get; set; }

    /// <summary>
    /// Role inside an HA pair: "standby" | "active" (null = not part of a pair). The
    /// standby-first strategy of §21.4/§14.3 deploys standby members before active ones.
    /// </summary>
    public string? HaRole { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<CertificateStore> Stores { get; set; } = new List<CertificateStore>();
}

/// <summary>
/// A certificate store on a target: Windows LocalMachine\My, a JKS path + alias,
/// an Oracle wallet directory, a plain file-system path for nginx, etc.
/// </summary>
public class CertificateStore : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35). Carried on the child as well as the parent: a query that
    /// starts at the child would otherwise cross the tenant boundary the parent's filter draws.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public Guid TargetId { get; set; }
    public Target Target { get; set; } = null!;

    /// <summary>e.g. "windows-my", "jks", "oracle-wallet", "pem-file".</summary>
    public string StoreType { get; set; } = string.Empty;
    public string StorePath { get; set; } = string.Empty;
    public string? Alias { get; set; }
    public string ConfigJson { get; set; } = "{}";

    public DateTimeOffset CreatedAt { get; set; }

    public ICollection<DeploymentBinding> Bindings { get; set; } = new List<DeploymentBinding>();
}

/// <summary>
/// The deployment relationship between a logical certificate and a store/service —
/// "this certificate lives in this store and activates via this service binding".
/// </summary>
public class DeploymentBinding : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35). Carried on the child as well as the parent: a query that
    /// starts at the child would otherwise cross the tenant boundary the parent's filter draws.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;
    public Guid CertificateStoreId { get; set; }
    public CertificateStore CertificateStore { get; set; } = null!;

    /// <summary>Service activation config as JSON (e.g. {"service":"nginx","action":"reload"}).</summary>
    public string ServiceBindingJson { get; set; } = "{}";
    public string ActivationPolicyJson { get; set; } = "{}";

    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// A reference to a secret — never the secret itself. Points to a provider and a
/// secret identifier; plaintext secret material must never be stored here.
/// </summary>
public class CredentialRef : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35); every query is filtered to it. Left empty on construction
    /// and stamped at save time from the tenant in force, so a row cannot be created under the
    /// wrong tenant by forgetting to set it.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public CredentialType CredentialType { get; set; }
    public SecretProviderType Provider { get; set; }

    /// <summary>Provider-specific locator, e.g. "vault://prod/java/truststore".</summary>
    public string SecretIdentifier { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string AccessPolicyJson { get; set; } = "{}";

    /// <summary>Data-protection-encrypted secret material for the internal vault provider; never plaintext.</summary>
    public string? EncryptedSecret { get; set; }

    /// <summary>Last time the secret behind this reference was read, for access audit (§7.3).</summary>
    public DateTimeOffset? LastAccessedAt { get; set; }
    /// <summary>Who or what read it last — a user or a runner.</summary>
    public string? LastAccessedBy { get; set; }

    /// <summary>Rotation cadence in days; 0 disables the rotation reminder (§7.3).</summary>
    public int RotationIntervalDays { get; set; }
    public DateTimeOffset? LastRotatedAt { get; set; }
    /// <summary>Set when a rotation is requested but the new material has not been supplied yet.</summary>
    public bool RotationPending { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>Rotation due date derived from the cadence; null when rotation is not configured.</summary>
    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset? RotationDueAt =>
        RotationIntervalDays <= 0 ? null : (LastRotatedAt ?? CreatedAt).AddDays(RotationIntervalDays);
}
