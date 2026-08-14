using System.Text.Json;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Events;

/// <summary>
/// The publish half of the transactional outbox (design doc §28.2). Notifying does not send
/// anything — it adds a row to the caller's own <see cref="IRemoteSslDbContext"/>, so the event
/// commits exactly when the state change that caused it commits. A rolled-back deployment can
/// never announce itself, and a committed one can never stay silent because a webhook was down.
/// Delivery is the dispatcher's job, afterwards.
/// </summary>
public class OutboxNotificationSink(IRemoteSslDbContext db) : INotificationSink
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public void Notify(string eventType, object payload) => Enqueue(eventType, payload, null);

    /// <summary>Same as <see cref="Notify"/>, carrying the correlation id of the surrounding chain.</summary>
    public void Enqueue(string eventType, object payload, string? correlationId)
    {
        db.OutboxMessages.Add(new OutboxMessage
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            SchemaVersion = DomainEvents.SchemaVersion,
            PayloadJson = JsonSerializer.Serialize(payload, Json),
            CorrelationId = correlationId ?? CorrelationIdOf(payload),
            Status = OutboxStatus.Pending,
            OccurredAt = DateTimeOffset.UtcNow
        });
    }

    /// <summary>
    /// Most call sites already put a correlation id in the payload; lifting it onto the row keeps
    /// the trace intact without every caller having to pass it twice.
    /// </summary>
    private static string? CorrelationIdOf(object payload)
    {
        var property = payload.GetType().GetProperty("correlationId") ?? payload.GetType().GetProperty("CorrelationId");
        return property?.GetValue(payload) as string;
    }
}
