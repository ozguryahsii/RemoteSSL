using System.Text.Json;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Auditing;

/// <summary>Appends sanitized audit events; caller must never pass secrets in details.</summary>
public class AuditWriter(IRemoteSslDbContext db)
{
    public void Append(string actor, string action, string objectType, string? objectId,
        string result, object? details = null, string? correlationId = null, Guid? targetId = null)
    {
        db.AuditEvents.Add(new AuditEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Actor = actor,
            Action = action,
            ObjectType = objectType,
            ObjectId = objectId,
            TargetId = targetId,
            Result = result,
            CorrelationId = correlationId ?? Guid.NewGuid().ToString("N"),
            DetailsJson = details is null ? "{}" : JsonSerializer.Serialize(details)
        });
    }
}
