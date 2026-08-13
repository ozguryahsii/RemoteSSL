namespace RemoteSSL.Domain.Entities;

/// <summary>
/// A managed deployment target (Linux/Windows server, network device, application).
/// Unlike a MonitorEndpoint, a Target carries a connection method, an adapter type and
/// a credential reference, and therefore supports install/activate/rollback actions.
/// </summary>
public class Target
{
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

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<CertificateStore> Stores { get; set; } = new List<CertificateStore>();
}

/// <summary>
/// A certificate store on a target: Windows LocalMachine\My, a JKS path + alias,
/// an Oracle wallet directory, a plain file-system path for nginx, etc.
/// </summary>
public class CertificateStore
{
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
public class DeploymentBinding
{
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
public class CredentialRef
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public CredentialType CredentialType { get; set; }
    public SecretProviderType Provider { get; set; }

    /// <summary>Provider-specific locator, e.g. "vault://prod/java/truststore".</summary>
    public string SecretIdentifier { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string AccessPolicyJson { get; set; } = "{}";

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
