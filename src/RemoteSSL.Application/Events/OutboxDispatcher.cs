using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Events;

/// <summary>
/// Drains the outbox (design doc §28.2). Each pending message is offered to every channel that
/// wants it; channels that accept are recorded on the row, so a retry only re-attempts the ones
/// that failed. After the retry budget is spent the message is marked failed and a
/// <c>notification.delivery-failed</c> event is raised — the failure of the notification path is
/// itself notified, which is what §33 asks for.
/// </summary>
public class OutboxDispatcher(
    IRemoteSslDbContext db,
    IEnumerable<INotificationChannel> channels,
    NotificationHealth health,
    AuditWriter audit)
{
    /// <summary>Attempts before a message is given up on and alarmed.</summary>
    public const int MaxAttempts = 6;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Dispatches one batch. Returns how many messages reached a terminal state.</summary>
    public async Task<int> DispatchBatchAsync(DateTimeOffset now, int batchSize, CancellationToken ct)
    {
        var pending = await db.OutboxMessages
            .Where(m => m.Status == OutboxStatus.Pending
                        && (m.NextAttemptAt == null || m.NextAttemptAt <= now))
            .OrderBy(m => m.OccurredAt)
            .Take(batchSize)
            .ToListAsync(ct);

        if (pending.Count == 0) return 0;

        var settled = 0;
        foreach (var message in pending)
        {
            var envelope = new EventEnvelope(message.Id, message.EventType, message.SchemaVersion,
                message.OccurredAt, message.CorrelationId, message.PayloadJson);

            var delivered = JsonSerializer.Deserialize<List<string>>(message.DeliveredChannelsJson, Json) ?? [];
            var errors = new List<string>();

            foreach (var channel in channels.Where(c => c.Enabled && !delivered.Contains(c.Name)))
            {
                if (!channel.Handles(envelope)) { delivered.Add(channel.Name); continue; }
                try
                {
                    await channel.SendAsync(envelope, ct);
                    delivered.Add(channel.Name);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    health.RecordFailure(channel.Name, message.EventType, ex);
                    errors.Add($"{channel.Name}: {ex.Message}");
                }
            }

            message.Attempts++;
            message.DeliveredChannelsJson = JsonSerializer.Serialize(delivered, Json);

            if (errors.Count == 0)
            {
                message.Status = OutboxStatus.Dispatched;
                message.DispatchedAt = now;
                message.LastError = null;
                settled++;
            }
            else
            {
                message.LastError = string.Join("; ", errors);
                if (message.Attempts >= MaxAttempts)
                {
                    message.Status = OutboxStatus.Failed;
                    settled++;
                    RaiseDeliveryFailure(message, now);
                }
                else
                {
                    // Exponential backoff: 30s, 1m, 2m, 4m, 8m — long enough to ride out a
                    // restart of the far end, short enough that an alert is not stale.
                    message.NextAttemptAt = now.AddSeconds(30 * Math.Pow(2, message.Attempts - 1));
                }
            }
        }

        await db.SaveChangesAsync(ct);
        return settled;
    }

    /// <summary>
    /// Announces that an event could not be delivered. This goes through the outbox like anything
    /// else, so it reaches whichever channels are still working — but it never chains, because a
    /// failure of the failure event would otherwise loop forever.
    /// </summary>
    private void RaiseDeliveryFailure(OutboxMessage message, DateTimeOffset now)
    {
        audit.Append("system", "notification.delivery-failed", "outbox_message", message.Id.ToString(),
            "FAILED", new { message.EventType, message.Attempts, message.LastError }, message.CorrelationId);

        if (message.EventType == DomainEvents.NotificationDeliveryFailed) return;

        db.OutboxMessages.Add(new OutboxMessage
        {
            Id = Guid.NewGuid(),
            EventType = DomainEvents.NotificationDeliveryFailed,
            SchemaVersion = DomainEvents.SchemaVersion,
            PayloadJson = JsonSerializer.Serialize(new
            {
                failedEventId = message.Id,
                failedEventType = message.EventType,
                message.Attempts,
                error = message.LastError
            }, Json),
            CorrelationId = message.CorrelationId,
            Status = OutboxStatus.Pending,
            OccurredAt = now
        });
    }

    /// <summary>
    /// Removes long-dispatched messages. Failed ones stay: they are the record of something that
    /// never reached its destination, and an operator has to be able to find them.
    /// </summary>
    public async Task<int> PruneAsync(DateTimeOffset olderThan, CancellationToken ct)
    {
        var stale = await db.OutboxMessages
            .Where(m => m.Status == OutboxStatus.Dispatched && m.DispatchedAt < olderThan)
            .Take(1000)
            .ToListAsync(ct);
        if (stale.Count == 0) return 0;
        db.OutboxMessages.RemoveRange(stale);
        await db.SaveChangesAsync(ct);
        return stale.Count;
    }
}
