namespace RemoteSSL.Domain.Entities;

/// <summary>Generic unit of work executed by a runner (connection test, deployment step batch…).</summary>
public class RunnerJob
{
    public Guid Id { get; set; }
    /// <summary>Pinned runner, or null = any runner may claim.</summary>
    public Guid? RunnerId { get; set; }
    /// <summary>"test-connection" | "deploy" | "rollback" | "discover" | "generate-csr".</summary>
    public string JobType { get; set; } = string.Empty;
    public string PayloadJson { get; set; } = "{}";
    public string Status { get; set; } = "Queued"; // Queued|Claimed|Running|Succeeded|Failed
    public string? ResultJson { get; set; }
    public string CorrelationId { get; set; } = string.Empty;
    public Guid? DeploymentJobTargetId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ClaimedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
}

/// <summary>CA connector instance configuration; secrets inside ConfigJson are stored encrypted.</summary>
public class CaConnectorConfig
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    /// <summary>"manual" | "globalsign-hvca" | future types.</summary>
    public string ConnectorType { get; set; } = string.Empty;
    public string EncryptedConfigJson { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}

public class CertificateRequestEntity
{
    public Guid Id { get; set; }
    public Guid? CertificateId { get; set; }
    public string CommonName { get; set; } = string.Empty;
    public string SansJson { get; set; } = "[]";
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySizeOrCurve { get; set; } = 2048;
    /// <summary>"central" (control plane) | "target" | "hsm".</summary>
    public string KeyOrigin { get; set; } = "central";
    /// <summary>On-target key origin: target that generates and keeps the private key.</summary>
    public Guid? TargetId { get; set; }
    /// <summary>On-target key origin: absolute path of the key file on the target.</summary>
    public string? TargetKeyPath { get; set; }
    public Guid? CaConnectorId { get; set; }
    public string? ProfileId { get; set; }
    public CertificateRequestState State { get; set; }
    public string? ProviderRequestId { get; set; }
    public string? CsrPem { get; set; }
    /// <summary>Data-protection-encrypted private key PEM when key origin is central; cleared after issuance binding.</summary>
    public string? EncryptedPrivateKeyPem { get; set; }
    public string? ErrorMessage { get; set; }
    public string? RequestedBy { get; set; }
    /// <summary>Target environment; drives approval and maintenance-window governance (§23.2).</summary>
    public string? Environment { get; set; }
    /// <summary>Owning user/team, required when the policy says so (§17.2).</summary>
    public string? OwnerId { get; set; }
    /// <summary>Trace id shared by the whole request → CA → deployment → runner chain (§32.2).</summary>
    public string CorrelationId { get; set; } = string.Empty;
    public Guid? IssuedVersionId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class RenewalPolicy
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public int TriggerDays { get; set; } = 30;
    public bool RotateKey { get; set; } = true;
    public bool AutoDeploy { get; set; }
    public bool ApprovalRequired { get; set; }
    /// <summary>e.g. {"days":["SUN"],"start":"01:00","end":"04:00"}; null = anytime.</summary>
    public string? MaintenanceWindowJson { get; set; }
    public Guid? CaConnectorId { get; set; }
    public string? ProfileId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Maker-checker record (§23.1). Covers both deployment jobs and certificate requests —
/// §19.1 puts a PENDING_APPROVAL step in the request state machine too.
/// </summary>
public class ApprovalRequest
{
    public Guid Id { get; set; }
    /// <summary>"deployment_job" | "certificate_request".</summary>
    public string ObjectType { get; set; } = "deployment_job";
    /// <summary>Set for deployment-job approvals; null for certificate-request approvals.</summary>
    public Guid? DeploymentJobId { get; set; }
    /// <summary>Set for certificate-request approvals; null for deployment-job approvals.</summary>
    public Guid? CertificateRequestId { get; set; }
    /// <summary>True when a break-glass administrator overrode separation of duties (§23.3).</summary>
    public bool BreakGlass { get; set; }
    public string Status { get; set; } = "Pending"; // Pending|Approved|Rejected
    public string? RequestedBy { get; set; }
    public string? DecidedBy { get; set; }
    public string? Reason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
}

/// <summary>
/// Ordered chain of monitor endpoints representing the hops in front of an
/// application (e.g. F5 VIP -> nginx -> IIS backend). Path analysis probes every
/// hop and pinpoints the layer serving a stale or mismatching certificate.
/// </summary>
public class ServicePath
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    /// <summary>Ordered JSON array of monitor endpoint ids (outermost hop first).</summary>
    public string MonitorIdsJson { get; set; } = "[]";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class UserAccount
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    /// <summary>JSON array, e.g. ["Admin"] — roles per design doc §24.1.</summary>
    public string RolesJson { get; set; } = "[]";
    /// <summary>
    /// JSON array of scope rules (§24.2): action + environment/targetGroup/adapter limits.
    /// Empty = the user's roles alone decide, which is the pre-scope behaviour.
    /// </summary>
    public string ScopesJson { get; set; } = "[]";
    /// <summary>Subject from the identity provider when the account is federated (§4.3).</summary>
    public string? ExternalSubject { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}
