namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Logical certificate identity (CN/SAN/ownership/policy). The central entity of the
/// inventory: monitor endpoints and deployment bindings hang off it, and every
/// issuance/renewal produces a new immutable <see cref="CertificateVersion"/>.
/// </summary>
public class Certificate
{
    public Guid Id { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string CommonName { get; set; } = string.Empty;
    public string? Environment { get; set; }
    public string? OwnerId { get; set; }
    public Guid? RenewalPolicyId { get; set; }
    public CertificateHealthStatus HealthStatus { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<CertificateVersion> Versions { get; set; } = new List<CertificateVersion>();
    public ICollection<MonitorCertificateLink> MonitorLinks { get; set; } = new List<MonitorCertificateLink>();
}

/// <summary>
/// Immutable result of a single issuance/renewal (or an observation of an unknown
/// certificate seen on a monitored endpoint). Never mutated after creation; renewal
/// creates a new version linked to the same logical certificate.
/// </summary>
public class CertificateVersion
{
    public Guid Id { get; set; }
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;

    public string SerialNumber { get; set; } = string.Empty;
    public string Sha256Thumbprint { get; set; } = string.Empty;
    public string Sha1Thumbprint { get; set; } = string.Empty;
    public string SubjectDn { get; set; } = string.Empty;
    public string IssuerDn { get; set; } = string.Empty;
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public string PublicKeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public CertificateVersionStatus Status { get; set; }

    /// <summary>PEM of the leaf certificate (public material only — never key material).</summary>
    public string? PemCertificate { get; set; }
    /// <summary>PEM bundle of the observed/assembled intermediate chain, in order.</summary>
    public string? PemChain { get; set; }

    /// <summary>Data-protection-encrypted private key PEM (central key origin only; design doc §16.2 tradeoff).</summary>
    public string? EncryptedPrivateKeyPem { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public ICollection<CertificateSan> Sans { get; set; } = new List<CertificateSan>();
}

public class CertificateSan
{
    public Guid Id { get; set; }
    public Guid CertificateVersionId { get; set; }
    public CertificateVersion CertificateVersion { get; set; } = null!;
    public SanType SanType { get; set; }
    public string Value { get; set; } = string.Empty;
}
