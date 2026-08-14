using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Events;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// The event outbox as an operator sees it (design doc §28.2, §33): what is waiting, what was
/// delivered, and — the part that matters — what never arrived and why. A failed event can be
/// requeued once the channel behind it is fixed.
/// </summary>
[ApiController]
[Route("api/v1/events")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "Auditor")]
public class EventsController(
    IRemoteSslDbContext db, NotificationHealth health,
    IEnumerable<INotificationChannel> channels, AuditWriter audit) : ControllerBase
{
    [HttpGet]
    public async Task<IEnumerable<object>> List(string? status, string? eventType, int take, CancellationToken ct)
    {
        var query = db.OutboxMessages.AsNoTracking().AsQueryable();
        if (Enum.TryParse<OutboxStatus>(status, true, out var parsed))
            query = query.Where(m => m.Status == parsed);
        if (!string.IsNullOrWhiteSpace(eventType))
            query = query.Where(m => m.EventType == eventType);

        return await query
            .OrderByDescending(m => m.OccurredAt)
            .Take(take is > 0 and <= 500 ? take : 100)
            .Select(m => new
            {
                m.Id, m.EventType, m.SchemaVersion, Status = m.Status.ToString(), m.CorrelationId,
                m.OccurredAt, m.DispatchedAt, m.Attempts, m.NextAttemptAt, m.LastError,
                m.DeliveredChannelsJson, m.PayloadJson
            })
            .ToListAsync(ct);
    }

    /// <summary>Which channels exist and which of them are actually configured here.</summary>
    [HttpGet("channels")]
    public IEnumerable<object> Channels() =>
        channels.Select(c => new { c.Name, c.Enabled });

    /// <summary>Delivery failures per channel over the last 24 hours (§33 alarm surface).</summary>
    [HttpGet("delivery-health")]
    public async Task<object> DeliveryHealth(CancellationToken ct) => new
    {
        Pending = await db.OutboxMessages.CountAsync(m => m.Status == OutboxStatus.Pending, ct),
        Failed = await db.OutboxMessages.CountAsync(m => m.Status == OutboxStatus.Failed, ct),
        FailuresByChannel = health.CountsByChannel(TimeSpan.FromHours(24)),
        Recent = health.Recent(TimeSpan.FromHours(24)).Take(20)
    };

    /// <summary>
    /// Puts a failed event back in the queue. Channels that already accepted it are remembered,
    /// so a retry only re-attempts the ones that failed — nobody gets the same event twice.
    /// </summary>
    [HttpPost("{id:guid}/retry")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
    public async Task<IActionResult> Retry(Guid id, CancellationToken ct)
    {
        var message = await db.OutboxMessages.FirstOrDefaultAsync(m => m.Id == id, ct);
        if (message is null) return NotFound();
        if (message.Status == OutboxStatus.Dispatched)
            return ValidationProblem("This event was already delivered to every channel that wanted it.");

        message.Status = OutboxStatus.Pending;
        message.Attempts = 0;
        message.NextAttemptAt = null;
        audit.Append(Actor(), "event.retry", "outbox_message", id.ToString(), "OK",
            new { message.EventType, message.LastError }, message.CorrelationId);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private string Actor() => User.Identity?.Name is { Length: > 0 } name ? $"user:{name}" : "user:api";
}
