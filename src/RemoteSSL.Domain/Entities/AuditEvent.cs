namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Append-only audit record (design doc §25). The application never updates or deletes a row —
/// removal happens only through the retention policy, and the database refuses the rest with a
/// trigger. Once sealed, each row carries the hash of its predecessor, so removing or editing any
/// row in the middle breaks the chain and is detectable (ADR-007).
/// </summary>
public class AuditEvent
{
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    /// <summary>Actor identity: "user:{name}", "service:{name}" or "runner:{id}".</summary>
    public string Actor { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string ObjectType { get; set; } = string.Empty;
    public string? ObjectId { get; set; }
    public Guid? TargetId { get; set; }
    public string Result { get; set; } = string.Empty;
    public string CorrelationId { get; set; } = string.Empty;
    /// <summary>Sanitized detail payload — must never contain secrets or key material.</summary>
    public string DetailsJson { get; set; } = "{}";

    // §25.1 context: who was really there, from where, and under which authority.

    /// <summary>Authentication session the action was taken in; ties several actions to one login.</summary>
    public string? SessionId { get; set; }
    /// <summary>Caller address as the API saw it, honouring the forwarded-headers configuration.</summary>
    public string? SourceIp { get; set; }
    /// <summary>Client/device string, for telling a browser apart from a script or a runner.</summary>
    public string? UserAgent { get; set; }
    /// <summary>The approval this action relied on, when it needed one (§23.3).</summary>
    public string? ApprovalReference { get; set; }

    /// <summary>Certificate thumbprint before the change; null when nothing was replaced.</summary>
    public string? OldFingerprint { get; set; }
    /// <summary>Certificate thumbprint after the change.</summary>
    public string? NewFingerprint { get; set; }

    // Hash chain (§25.3, ADR-007). Assigned by the sealing pass, not at insert, so concurrent
    // writers never contend over the chain head.

    /// <summary>Position in the chain; 0 until the row is sealed.</summary>
    public long Sequence { get; set; }
    /// <summary>Hash of the previous sealed row; null for the first row in the chain.</summary>
    public string? PreviousHash { get; set; }
    /// <summary>SHA-256 over this row's content and <see cref="PreviousHash"/>; null until sealed.</summary>
    public string? Hash { get; set; }
    public DateTimeOffset? SealedAt { get; set; }
    /// <summary>Set once the row has been written to the external WORM copy (§25.3).</summary>
    public DateTimeOffset? ArchivedAt { get; set; }
}
