namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// One domain event, as every channel sees it (design doc §28.1). The envelope is the contract:
/// consumers get the event name, a schema version, when it happened, the correlation id that ties
/// it to the rest of the chain, and the payload.
/// </summary>
public sealed record EventEnvelope(
    Guid Id,
    string EventType,
    int SchemaVersion,
    DateTimeOffset OccurredAt,
    string? CorrelationId,
    string PayloadJson);

/// <summary>
/// A destination for domain events (design doc §33): chat, mail, message bus, SIEM, ITSM, paging.
/// Channels are independent — one failing never stops another, and each one decides for itself
/// which events it cares about.
/// </summary>
public interface INotificationChannel
{
    /// <summary>Stable name, recorded on the outbox row so a retry does not re-deliver.</summary>
    string Name { get; }

    /// <summary>False when the channel is compiled in but not configured; it is then skipped entirely.</summary>
    bool Enabled { get; }

    /// <summary>Whether this channel wants this particular event. Paging channels want very few.</summary>
    bool Handles(EventEnvelope envelope);

    /// <summary>Delivers the event. Throwing means "retry me"; returning means delivered.</summary>
    Task SendAsync(EventEnvelope envelope, CancellationToken ct);
}
