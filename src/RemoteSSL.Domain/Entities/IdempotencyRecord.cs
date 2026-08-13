namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Replay record for the <c>Idempotency-Key</c> header of design doc §27.2. Stores the
/// first response for a key so a retried create returns the same job/request instead of
/// making a second one. Contains no secret material — only the response the caller
/// already received and a hash of the request body.
/// </summary>
public class IdempotencyRecord
{
    public long Id { get; set; }
    public string Key { get; set; } = string.Empty;
    /// <summary>"POST /api/v1/deployments" — a key is scoped to the endpoint it was used on.</summary>
    public string Endpoint { get; set; } = string.Empty;
    /// <summary>SHA-256 of the request arguments, to detect a key reused with a different body.</summary>
    public string RequestFingerprint { get; set; } = string.Empty;
    public int StatusCode { get; set; }
    public string ResponseJson { get; set; } = "null";
    public DateTimeOffset CreatedAt { get; set; }
}
