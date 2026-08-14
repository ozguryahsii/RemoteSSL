namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Certificate policy of design doc §39, extended with the request-validation rules of
/// §17.2 and the environment governance matrix of §23.2. One policy is marked default and
/// applies to everything that has no policy of its own.
/// </summary>
public class CertificatePolicy : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35); every query is filtered to it. Left empty on construction
    /// and stamped at save time from the tenant in force, so a row cannot be created under the
    /// wrong tenant by forgetting to set it.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    /// <summary>Applied when a certificate/request has no explicit policy.</summary>
    public bool IsDefault { get; set; }

    // ---- §39 certificatePolicy ------------------------------------------------
    public int MinimumRsaBits { get; set; } = 2048;
    /// <summary>JSON array, e.g. ["P-256","P-384"].</summary>
    public string AllowedEcCurvesJson { get; set; } = """["P-256","P-384"]""";
    public int RenewBeforeDays { get; set; } = 30;
    public bool RotateKeyOnRenewal { get; set; } = true;
    /// <summary>JSON array of environments needing maker-checker approval, e.g. ["PROD"].</summary>
    public string RequireApprovalInJson { get; set; } = """["PROD"]""";
    public bool BlockWeakSignatureAlgorithms { get; set; } = true;
    public bool RequirePostDeploymentProbe { get; set; } = true;

    // ---- §17.2 request validation ---------------------------------------------
    public bool AllowWildcard { get; set; } = true;
    /// <summary>Null = unlimited; otherwise the longest validity a request may ask a CA for.</summary>
    public int? MaxValidityDays { get; set; }
    /// <summary>JSON array of permitted name suffixes; empty = any hostname allowed.</summary>
    public string AllowedDomainSuffixesJson { get; set; } = "[]";
    /// <summary>JSON array of suffixes that may never be requested (e.g. [".local",".internal"]).</summary>
    public string BlockedDomainSuffixesJson { get; set; } = "[]";
    /// <summary>Warn when the requested names overlap a certificate already in the inventory.</summary>
    public bool WarnOnOverlap { get; set; } = true;
    /// <summary>Every request must name an owner before it can be submitted.</summary>
    public bool RequireOwner { get; set; }

    // ---- §23.2 / §23.3 governance ---------------------------------------------
    /// <summary>
    /// JSON array of environments where deployment may only run inside the maintenance
    /// window. §23.2 leaves this optional, so the default is empty and admins opt in.
    /// </summary>
    public string RequireWindowInJson { get; set; } = "[]";
    /// <summary>Requester may not approve their own change; break-glass overrides but is audited.</summary>
    public bool EnforceSeparationOfDuties { get; set; } = true;

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
