namespace RemoteSSL.Domain.Entities;

/// <summary>Where a domain validation stands (design doc §18.1).</summary>
public enum DomainValidationState
{
    /// <summary>The CA has told us what to publish; nobody has published it yet.</summary>
    Pending = 0,
    /// <summary>The operator says it is published and the CA has been asked to check.</summary>
    Submitted,
    Valid,
    Failed,
    Expired
}

/// <summary>
/// One outstanding proof of domain control (design doc §18.1). ACME challenges and commercial-CA
/// domain claims differ in wording but not in shape: a name, a method, something to publish, and a
/// deadline. Holding them as rows is what lets the UI show an operator exactly what to do and lets
/// the platform re-check without asking the CA to start over.
/// </summary>
public class DomainValidation : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35). Carried on the child as well as the parent: a query that
    /// starts at the child would otherwise cross the tenant boundary the parent's filter draws.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public Guid CertificateRequestId { get; set; }
    public Guid CaConnectorId { get; set; }

    public string Domain { get; set; } = string.Empty;
    /// <summary>"dns-01", "http-01", or the CA's own method name.</summary>
    public string Method { get; set; } = string.Empty;
    public DomainValidationState State { get; set; }

    /// <summary>Provider handle used to tell the CA the proof is in place — an ACME challenge URL.</summary>
    public string ChallengeReference { get; set; } = string.Empty;
    /// <summary>The DNS record to publish, ready to paste; null for methods that need none.</summary>
    public string? ExpectedDnsRecord { get; set; }
    /// <summary>The HTTP path and body to serve; null for methods that need none.</summary>
    public string? ExpectedHttpResponse { get; set; }

    public string? Detail { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? SubmittedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
}
