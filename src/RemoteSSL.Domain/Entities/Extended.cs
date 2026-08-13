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

public class ApprovalRequest
{
    public Guid Id { get; set; }
    public Guid DeploymentJobId { get; set; }
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
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}
