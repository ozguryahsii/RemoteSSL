namespace RemoteSSL.Domain.Entities;

/// <summary>
/// An execution node living inside a network segment. Connects outbound (mTLS) to the
/// control plane, publishes its capabilities via heartbeat and executes deployment
/// jobs against targets it can reach; the control plane never connects to targets
/// directly.
/// </summary>
public class RunnerNode : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35); every query is filtered to it. Left empty on construction
    /// and stamped at save time from the tenant in force, so a row cannot be created under the
    /// wrong tenant by forgetting to set it.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Segment { get; set; }
    public RunnerStatus Status { get; set; }

    /// <summary>Capabilities advertised via heartbeat, e.g. ["ssh","winrm","openssl","keytool"].</summary>
    public string CapabilitiesJson { get; set; } = "[]";
    public string? Version { get; set; }

    /// <summary>SHA-256 thumbprint of the runner's client identity certificate.</summary>
    public string? IdentityCertThumbprint { get; set; }

    /// <summary>SHA-256 hash of the runner's API key (issued at registration; plaintext never stored).</summary>
    public string? ApiKeyHash { get; set; }

    /// <summary>Set when the runner's identity certificate was revoked (§8.2, §30.2).</summary>
    public DateTimeOffset? IdentityRevokedAt { get; set; }
    public string? IdentityRevokedReason { get; set; }

    /// <summary>
    /// Adapter versions the runner reports at heartbeat, as JSON {"nginx":"1.2.0",…}. Version
    /// pinning (§30.2 supply chain) compares this against the allowlist before dispatching.
    /// </summary>
    public string AdapterVersionsJson { get; set; } = "{}";

    /// <summary>
    /// Affinity group (design doc §34.2). Runners in the same group can reach the same targets, so
    /// a job orphaned by one of them may be handed to another in the group — and to no one else.
    /// </summary>
    public string? AffinityGroup { get; set; }

    public DateTimeOffset? LastHeartbeatAt { get; set; }
    public DateTimeOffset RegisteredAt { get; set; }
}


/// <summary>
/// The control plane's internal CA for runner identity certificates (§8.2). Its only job is
/// signing runner client certificates, so it is deliberately separate from the CA connectors
/// that issue server certificates.
/// </summary>
public class RunnerCertificateAuthority
{
    public Guid Id { get; set; }
    public string CertificatePem { get; set; } = string.Empty;
    /// <summary>Data-protection encrypted PKCS#8 key; never returned by any API.</summary>
    public string EncryptedKeyPem { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}
