namespace RemoteSSL.Domain.Entities;

/// <summary>Where an outbox message is in its life (design doc §28.2).</summary>
public enum OutboxStatus
{
    Pending = 0,
    Dispatched,
    /// <summary>Every channel that had to take it failed past the retry budget; it is alarmed, not silently dropped.</summary>
    Failed
}

/// <summary>
/// A domain event waiting to be published (design doc §28.2, transactional outbox). The row is
/// written in the same transaction as the state change that produced it, so an event can never
/// describe a change that was rolled back, and a committed change can never lose its event.
/// Publishing happens afterwards, out of band, and may retry as often as it needs to.
/// </summary>
public class OutboxMessage
{
    public Guid Id { get; set; }
    /// <summary>One of <c>DomainEvents</c>; also the RabbitMQ routing key.</summary>
    public string EventType { get; set; } = string.Empty;
    public int SchemaVersion { get; set; } = 1;
    public string PayloadJson { get; set; } = "{}";
    /// <summary>Ties the event to the request → CA → job → runner chain (§32.2).</summary>
    public string? CorrelationId { get; set; }

    public OutboxStatus Status { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public DateTimeOffset? DispatchedAt { get; set; }

    public int Attempts { get; set; }
    /// <summary>When the dispatcher may try again; set by exponential backoff after a failure.</summary>
    public DateTimeOffset? NextAttemptAt { get; set; }
    public string? LastError { get; set; }

    /// <summary>Channels that already accepted this message, so a retry does not re-deliver them.</summary>
    public string DeliveredChannelsJson { get; set; } = "[]";
}
