namespace RemoteSSL.Application.Auditing;

/// <summary>
/// Who was really there, and from where (design doc §25.1). Filled in per request from the HTTP
/// context and read by <see cref="AuditWriter"/>, so no call site has to pass it along. Empty for
/// work that has no caller — schedulers and background passes.
/// </summary>
public class AuditContext
{
    /// <summary>Authentication session the request belongs to; ties several actions to one login.</summary>
    public string? SessionId { get; set; }
    public string? SourceIp { get; set; }
    public string? UserAgent { get; set; }
}
