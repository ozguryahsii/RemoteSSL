using System.Text.Json;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Auditing;

/// <summary>Appends sanitized audit events; caller must never pass secrets in details.</summary>
public class AuditWriter(IRemoteSslDbContext db, IConfiguration? configuration = null)
{
    /// <summary>
    /// Mirrors every audit row into the outbox as an <c>audit.*</c> event when
    /// <c>Integrations:ForwardAuditToSiem</c> is on (design doc §25.3). The mirror rides the same
    /// transaction as the audit row itself, so the SIEM copy and the local record cannot diverge.
    /// </summary>
    private bool ForwardToSiem =>
        string.Equals(configuration?["Integrations:ForwardAuditToSiem"], "true", StringComparison.OrdinalIgnoreCase);

    public void Append(string actor, string action, string objectType, string? objectId,
        string result, object? details = null, string? correlationId = null, Guid? targetId = null)
    {
        var trace = correlationId ?? Guid.NewGuid().ToString("N");
        var detailsJson = details is null ? "{}" : JsonSerializer.Serialize(details);

        db.AuditEvents.Add(new AuditEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Actor = actor,
            Action = action,
            ObjectType = objectType,
            ObjectId = objectId,
            TargetId = targetId,
            Result = result,
            CorrelationId = trace,
            DetailsJson = detailsJson
        });

        if (!ForwardToSiem) return;

        db.OutboxMessages.Add(new OutboxMessage
        {
            Id = Guid.NewGuid(),
            EventType = "audit." + action,
            SchemaVersion = Events.DomainEvents.SchemaVersion,
            PayloadJson = JsonSerializer.Serialize(new
            {
                actor, action, objectType, objectId, result,
                targetId,
                details = JsonDocument.Parse(detailsJson).RootElement
            }),
            CorrelationId = trace,
            Status = OutboxStatus.Pending,
            OccurredAt = DateTimeOffset.UtcNow
        });
    }
}
