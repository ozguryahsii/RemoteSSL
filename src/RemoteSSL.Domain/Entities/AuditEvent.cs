namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Append-only audit record. Rows are never updated or deleted by the application;
/// removal happens only via retention policy.
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
}
