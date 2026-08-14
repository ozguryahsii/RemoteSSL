namespace RemoteSSL.Domain;

public enum CertificateHealthStatus
{
    Unknown = 0,
    Healthy,
    ExpiringSoon,
    Critical,
    Expired,
    Revoked,
    Superseded,
    PendingDeployment,
    PartiallyDeployed,
    DeploymentFailed,
    Unreachable
}

public enum CertificateVersionStatus
{
    Observed = 0,   // discovered via monitoring, not issued by us
    Issued,
    Active,
    Superseded,
    Revoked,
    Expired
}

public enum CertificateRequestState
{
    Draft = 0,
    Validated,
    PendingApproval,
    Rejected,
    CsrGenerated,
    SubmittedToCa,
    PendingIssuance,
    WaitingForCertificate, // manual CA fallback
    Issued,
    ReadyForDeployment,
    Active,
    RenewalDue,
    Renewing,
    FailedRetryable,
    FailedBlocked
}

public enum ProbeStatus
{
    NeverProbed = 0,
    Success,
    ConnectionFailed,
    TlsHandshakeFailed,
    Timeout,
    DnsResolutionFailed
}

public enum TargetType
{
    LinuxServer = 0,
    WindowsServer,
    NetworkDevice,
    Application,
    CloudService
}

public enum CredentialType
{
    UsernamePassword = 0,
    SshPrivateKey,
    SshCertificate,
    KerberosServiceAccount,
    ApiKeySecret,
    OAuthClientCredentials,
    BearerToken,
    ClientCertificate,
    ExternalSecretReference
}

public enum SecretProviderType
{
    InternalVault = 0,
    HashiCorpVault,
    CyberArk,
    AzureKeyVault
}

/// <summary>Where a private key physically lives (§16.3).</summary>
public enum KeyProviderKind
{
    /// <summary>Control-plane software key, encrypted at rest.</summary>
    Software = 0,
    /// <summary>A PKCS#11 token — an on-prem HSM or a smartcard-style device.</summary>
    Pkcs11,
    /// <summary>A cloud KMS / managed HSM key, referenced by URI and used through its own API.</summary>
    CloudKms
}

public enum DeploymentJobStatus
{
    Pending = 0,
    PendingApproval,
    Approved,
    Scheduled,
    Running,
    Succeeded,
    PartiallyFailed,
    Failed,
    RolledBack,
    RollbackFailed,
    Cancelled
}

public enum DeploymentStepType
{
    PreCheck = 0,
    Backup,
    PrepareUpload,
    Install,
    ConfigValidate,
    Activate,
    Reload,
    LocalVerify,
    RemoteVerify,
    Commit,
    Rollback,
    VerifyRollback,
    Cleanup
}

public enum StepStatus
{
    Pending = 0,
    Running,
    Succeeded,
    Failed,
    Skipped
}

public enum RunnerStatus
{
    Registered = 0,
    Online,
    Offline,
    Disabled
}

public enum SanType
{
    Dns = 0,
    Ip,
    Uri,
    Email
}

public enum ArtifactSensitivity
{
    Public = 0,          // leaf cert, chain, CSR
    Sensitive,           // PFX/P12 containing private key
    HighlySensitive,     // raw private key
    Backup               // old store/config backup
}
