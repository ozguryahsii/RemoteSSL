namespace RemoteSSL.Domain.Abstractions;

/// <summary>
/// Provider-agnostic CA connector contract. GlobalSign (HVCA/Atlas) is the first
/// planned implementation, but nothing GlobalSign-specific may leak into this
/// interface or the core domain model — provider specifics live in each connector's
/// own configuration JSON. The shape is informed by the HVCA workflow (authenticate →
/// read validation policy/profiles → submit CSR → poll status → download certificate
/// → revoke) which generalizes across ACME, AD CS, DigiCert, Sectigo and manual CAs.
/// </summary>
public interface ICertificateAuthorityConnector
{
    /// <summary>Stable connector identifier, e.g. "globalsign-hvca", "acme", "manual".</summary>
    string ConnectorType { get; }

    /// <summary>Verifies credentials/connectivity (e.g. HVCA mTLS + api key login).</summary>
    Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct);

    /// <summary>
    /// Lists issuing profiles/validation policies. Maps to HVCA validation policy,
    /// ACME directory, AD CS templates — normalized into <see cref="CaProfile"/>.
    /// </summary>
    Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct);

    /// <summary>Submits a PKCS#10 CSR; returns a provider-scoped request reference.</summary>
    Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId, IReadOnlyDictionary<string, string> metadata, CancellationToken ct);

    Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct);

    /// <summary>Downloads the issued leaf plus its chain, both PEM.</summary>
    Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct);

    Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId, CancellationToken ct);

    Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct);

    /// <summary>
    /// Optional domain-validation support (HVCA domain claims, ACME challenges).
    /// Connectors without DV return null.
    /// </summary>
    Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method, CancellationToken ct);
}

public sealed record CaConnectionResult(bool Success, string? Error = null);

/// <summary>Normalized issuing profile: key/validity/SAN constraints the wizard can enforce up front.</summary>
public sealed record CaProfile(
    string ProfileId,
    string DisplayName,
    IReadOnlyList<string> AllowedKeyAlgorithms,
    int MaxValidityDays,
    bool SupportsWildcard,
    string ProviderDetailsJson);

/// <summary>Opaque provider request handle persisted on CertificateRequest for polling/webhooks.</summary>
public sealed record CaRequestRef(string ConnectorType, string ProviderRequestId);

public enum CaRequestState
{
    Pending = 0,
    ValidationRequired,
    Issued,
    Rejected,
    Failed
}

public sealed record CaRequestStatus(CaRequestState State, string? Detail = null);

public sealed record IssuedCertificate(string LeafPem, string ChainPem, string SerialNumber);

public enum RevocationReason
{
    Unspecified = 0,
    KeyCompromise,
    Superseded,
    CessationOfOperation
}

public sealed record DomainValidationChallenge(
    string Domain,
    string Method,
    string ChallengeToken,
    string? ExpectedDnsRecord,
    string? ExpectedHttpPath,
    DateTimeOffset? ExpiresAt);
