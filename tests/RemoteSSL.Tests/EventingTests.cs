using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Events;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Notifications;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>Transactional outbox and delivery — design doc §28.2, §33.</summary>
public class OutboxTests
{
    /// <summary>A channel that records what it was given, and fails on demand.</summary>
    private sealed class RecordingChannel(string name, bool enabled = true, bool alwaysFails = false,
        Func<EventEnvelope, bool>? filter = null) : INotificationChannel
    {
        public string Name => name;
        public bool Enabled => enabled;
        public List<EventEnvelope> Sent { get; } = [];
        public bool Failing { get; set; } = alwaysFails;

        public bool Handles(EventEnvelope envelope) => filter?.Invoke(envelope) ?? true;

        public Task SendAsync(EventEnvelope envelope, CancellationToken ct)
        {
            if (Failing) throw new HttpRequestException("channel is down");
            Sent.Add(envelope);
            return Task.CompletedTask;
        }
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"outbox-tests-{Guid.NewGuid()}").Options);

    private static OutboxDispatcher CreateDispatcher(
        RemoteSslDbContext db, NotificationHealth health, params INotificationChannel[] channels) =>
        new(db, channels, health, new AuditWriter(db));

    [Fact]
    public async Task Notifying_writes_a_row_but_sends_nothing_until_the_transaction_commits()
    {
        using var db = CreateDb();
        var sink = new OutboxNotificationSink(db);

        sink.Notify(DomainEvents.DeploymentCompleted, new { jobId = Guid.NewGuid() });
        Assert.Empty(await db.OutboxMessages.ToListAsync());

        await db.SaveChangesAsync();
        var message = await db.OutboxMessages.SingleAsync();
        Assert.Equal(DomainEvents.DeploymentCompleted, message.EventType);
        Assert.Equal(OutboxStatus.Pending, message.Status);
    }

    [Fact]
    public async Task A_correlation_id_in_the_payload_is_lifted_onto_the_row()
    {
        using var db = CreateDb();
        new OutboxNotificationSink(db).Notify(DomainEvents.DeploymentFailed, new { correlationId = "abc123" });
        await db.SaveChangesAsync();

        Assert.Equal("abc123", (await db.OutboxMessages.SingleAsync()).CorrelationId);
    }

    [Fact]
    public async Task A_dispatched_message_reaches_every_enabled_channel_that_wants_it()
    {
        using var db = CreateDb();
        var wanted = new RecordingChannel("wanted");
        var uninterested = new RecordingChannel("uninterested", filter: _ => false);
        var disabled = new RecordingChannel("disabled", enabled: false);

        new OutboxNotificationSink(db).Notify(DomainEvents.DeploymentCompleted, new { jobId = 1 });
        await db.SaveChangesAsync();

        var settled = await CreateDispatcher(db, new NotificationHealth(), wanted, uninterested, disabled)
            .DispatchBatchAsync(DateTimeOffset.UtcNow, 10, default);

        Assert.Equal(1, settled);
        Assert.Single(wanted.Sent);
        Assert.Empty(uninterested.Sent);
        Assert.Empty(disabled.Sent);
        Assert.Equal(OutboxStatus.Dispatched, (await db.OutboxMessages.SingleAsync()).Status);
    }

    [Fact]
    public async Task A_failing_channel_is_retried_with_backoff_while_the_others_are_not_re_sent()
    {
        using var db = CreateDb();
        var healthy = new RecordingChannel("healthy");
        var broken = new RecordingChannel("broken", alwaysFails: true);
        var health = new NotificationHealth();
        var dispatcher = CreateDispatcher(db, health, healthy, broken);

        new OutboxNotificationSink(db).Notify(DomainEvents.DeploymentCompleted, new { jobId = 1 });
        await db.SaveChangesAsync();

        var now = DateTimeOffset.UtcNow;
        await dispatcher.DispatchBatchAsync(now, 10, default);

        var message = await db.OutboxMessages.SingleAsync();
        Assert.Equal(OutboxStatus.Pending, message.Status);
        Assert.Equal(1, message.Attempts);
        Assert.NotNull(message.NextAttemptAt);
        Assert.True(message.NextAttemptAt > now);
        Assert.Contains("broken", message.LastError);
        Assert.Single(health.Recent(TimeSpan.FromMinutes(5)));

        // Second pass once the channel recovers: only the broken one is retried.
        broken.Failing = false;
        await dispatcher.DispatchBatchAsync(message.NextAttemptAt!.Value, 10, default);

        Assert.Single(healthy.Sent);
        Assert.Single(broken.Sent);
        Assert.Equal(OutboxStatus.Dispatched, (await db.OutboxMessages.SingleAsync()).Status);
    }

    [Fact]
    public async Task A_message_not_yet_due_is_left_alone()
    {
        using var db = CreateDb();
        var channel = new RecordingChannel("c");
        new OutboxNotificationSink(db).Notify(DomainEvents.DeploymentCompleted, new { jobId = 1 });
        await db.SaveChangesAsync();
        var message = await db.OutboxMessages.SingleAsync();
        message.NextAttemptAt = DateTimeOffset.UtcNow.AddMinutes(5);
        await db.SaveChangesAsync();

        var settled = await CreateDispatcher(db, new NotificationHealth(), channel)
            .DispatchBatchAsync(DateTimeOffset.UtcNow, 10, default);

        Assert.Equal(0, settled);
        Assert.Empty(channel.Sent);
    }

    [Fact]
    public async Task Exhausting_the_retry_budget_marks_the_message_failed_and_raises_its_own_event()
    {
        using var db = CreateDb();
        var broken = new RecordingChannel("broken", alwaysFails: true);
        var dispatcher = CreateDispatcher(db, new NotificationHealth(), broken);

        new OutboxNotificationSink(db).Notify(DomainEvents.DeploymentCompleted, new { jobId = 1 });
        await db.SaveChangesAsync();

        var now = DateTimeOffset.UtcNow;
        for (var attempt = 0; attempt < OutboxDispatcher.MaxAttempts; attempt++)
            await dispatcher.DispatchBatchAsync(now.AddHours(attempt), 10, default);

        var original = await db.OutboxMessages
            .FirstAsync(m => m.EventType == DomainEvents.DeploymentCompleted);
        Assert.Equal(OutboxStatus.Failed, original.Status);

        // The failure of the notification path is itself notified (§33).
        Assert.True(await db.OutboxMessages.AnyAsync(m => m.EventType == DomainEvents.NotificationDeliveryFailed));
        Assert.True(await db.AuditEvents.AnyAsync(e => e.Action == "notification.delivery-failed"));
    }

    [Fact]
    public async Task A_failed_delivery_event_does_not_spawn_another_one()
    {
        using var db = CreateDb();
        var broken = new RecordingChannel("broken", alwaysFails: true);
        var dispatcher = CreateDispatcher(db, new NotificationHealth(), broken);

        new OutboxNotificationSink(db).Notify(DomainEvents.NotificationDeliveryFailed, new { failedEventId = Guid.NewGuid() });
        await db.SaveChangesAsync();

        var now = DateTimeOffset.UtcNow;
        for (var attempt = 0; attempt < OutboxDispatcher.MaxAttempts; attempt++)
            await dispatcher.DispatchBatchAsync(now.AddHours(attempt), 10, default);

        // Exactly the one we enqueued — no cascade.
        Assert.Single(await db.OutboxMessages.ToListAsync());
    }

    [Fact]
    public async Task Pruning_removes_delivered_messages_and_keeps_failed_ones()
    {
        using var db = CreateDb();
        db.OutboxMessages.AddRange(
            new OutboxMessage
            {
                Id = Guid.NewGuid(), EventType = "a", Status = OutboxStatus.Dispatched,
                OccurredAt = DateTimeOffset.UtcNow.AddDays(-30), DispatchedAt = DateTimeOffset.UtcNow.AddDays(-30)
            },
            new OutboxMessage
            {
                Id = Guid.NewGuid(), EventType = "b", Status = OutboxStatus.Failed,
                OccurredAt = DateTimeOffset.UtcNow.AddDays(-30)
            });
        await db.SaveChangesAsync();

        var removed = await CreateDispatcher(db, new NotificationHealth())
            .PruneAsync(DateTimeOffset.UtcNow.AddDays(-14), default);

        Assert.Equal(1, removed);
        Assert.Equal("b", (await db.OutboxMessages.SingleAsync()).EventType);
    }

    [Fact]
    public async Task An_audit_row_is_mirrored_to_the_outbox_only_when_siem_forwarding_is_on()
    {
        using var off = CreateDb();
        new AuditWriter(off).Append("user:a", "certificate.revoke", "certificate", "1", "OK");
        await off.SaveChangesAsync();
        Assert.Empty(await off.OutboxMessages.ToListAsync());

        using var on = CreateDb();
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            [new KeyValuePair<string, string?>("Integrations:ForwardAuditToSiem", "true")]).Build();
        new AuditWriter(on, config).Append("user:a", "certificate.revoke", "certificate", "1", "OK");
        await on.SaveChangesAsync();

        var mirrored = await on.OutboxMessages.SingleAsync();
        Assert.Equal("audit.certificate.revoke", mirrored.EventType);
        Assert.Equal((await on.AuditEvents.SingleAsync()).CorrelationId, mirrored.CorrelationId);
    }
}

/// <summary>Event vocabulary and routing rules — design doc §28.1, §33.</summary>
public class DomainEventTests
{
    [Fact]
    public void Failures_are_more_severe_than_informational_events()
    {
        Assert.True(DomainEvents.SeverityOf(DomainEvents.DeploymentFailed)
                    < DomainEvents.SeverityOf(DomainEvents.CertificateExpiring));
        Assert.True(DomainEvents.SeverityOf(DomainEvents.CertificateExpiring)
                    < DomainEvents.SeverityOf(DomainEvents.DeploymentRequested));
    }

    [Fact]
    public void Only_incident_grade_events_page_someone()
    {
        Assert.Contains(DomainEvents.DeploymentFailed, DomainEvents.Incidents);
        Assert.Contains(DomainEvents.RollbackStarted, DomainEvents.Incidents);
        Assert.DoesNotContain(DomainEvents.DeploymentRequested, DomainEvents.Incidents);
        Assert.DoesNotContain(DomainEvents.CertificateDiscovered, DomainEvents.Incidents);
    }

    [Fact]
    public void Only_change_worthy_events_open_a_ticket()
    {
        Assert.Contains(DomainEvents.DeploymentApproved, DomainEvents.ChangeWorthy);
        Assert.DoesNotContain(DomainEvents.VantageMismatch, DomainEvents.ChangeWorthy);
    }

    [Fact]
    public void Audit_mirrors_are_recognised_by_their_prefix()
    {
        Assert.True(DomainEvents.IsAuditMirror("audit.certificate.revoke"));
        Assert.False(DomainEvents.IsAuditMirror(DomainEvents.CertificateRevoked));
    }
}

/// <summary>SIEM and ITSM wire formats — design doc §33, §25.3.</summary>
public class IntegrationChannelTests
{
    private static readonly EventEnvelope Sample = new(
        Guid.Parse("11111111-2222-3333-4444-555555555555"),
        DomainEvents.DeploymentFailed, 1,
        new DateTimeOffset(2026, 5, 4, 10, 30, 0, TimeSpan.Zero),
        "trace-42",
        """{"jobId":"7","reason":"nginx reload failed"}""");

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    [Fact]
    public void An_unconfigured_channel_reports_itself_disabled()
    {
        Assert.False(new SyslogChannel(Config()).Enabled);
        Assert.False(new ServiceNowChannel(new HttpFactoryStub(), Config()).Enabled);
        Assert.False(new PagerDutyChannel(new HttpFactoryStub(), Config()).Enabled);
        Assert.False(new OpsgenieChannel(new HttpFactoryStub(), Config()).Enabled);
    }

    [Fact]
    public void The_syslog_line_is_valid_rfc5424_with_the_right_priority()
    {
        var channel = new SyslogChannel(Config(
            ("Integrations:Syslog:Host", "siem.local"),
            ("Integrations:Syslog:Facility", "16"),
            ("Integrations:Syslog:Hostname", "clm01")));

        var line = channel.Rfc5424(Sample);

        // facility 16 * 8 + severity 3 (error) = 131
        Assert.StartsWith("<131>1 2026-05-04T10:30:00.000Z clm01 remotessl - deployment.failed ", line);
        Assert.Contains("correlationId=\"trace-42\"", line);
        Assert.Contains("nginx reload failed", line);
    }

    [Fact]
    public void The_cef_line_escapes_the_characters_that_would_break_the_format()
    {
        var channel = new SyslogChannel(Config(
            ("Integrations:Syslog:Host", "siem.local"), ("Integrations:Syslog:Format", "cef")));

        var line = channel.Cef(Sample with { PayloadJson = """{"a":"x|y=z"}""" });

        Assert.StartsWith("CEF:0|RemoteSSL|CLM|1.0|deployment.failed|deployment.failed|7|", line);
        Assert.Contains("x\\|y\\=z", line);
    }

    [Fact]
    public void Servicenow_only_takes_change_worthy_events()
    {
        var channel = new ServiceNowChannel(new HttpFactoryStub(), Config());
        Assert.True(channel.Handles(Sample));
        Assert.False(channel.Handles(Sample with { EventType = DomainEvents.VantageMismatch }));
    }

    [Fact]
    public void Paging_channels_only_take_incidents_and_deduplicate_on_the_correlation_id()
    {
        var pagerDuty = new PagerDutyChannel(new HttpFactoryStub(), Config());
        Assert.True(pagerDuty.Handles(Sample));
        Assert.False(pagerDuty.Handles(Sample with { EventType = DomainEvents.CertificateDiscovered }));

        var payload = System.Text.Json.JsonSerializer.Serialize(
            PagerDutyChannel.Payload(Sample, "routing-key"));
        Assert.Contains("remotessl:deployment.failed:trace-42", payload);
        Assert.Contains("\"severity\":\"error\"", payload);

        var opsgenie = System.Text.Json.JsonSerializer.Serialize(
            OpsgenieChannel.Payload(Sample, "platform"));
        Assert.Contains("remotessl:deployment.failed:trace-42", opsgenie);
        Assert.Contains("P1", opsgenie);
    }

    [Fact]
    public void A_servicenow_record_carries_the_correlation_id_and_an_urgency()
    {
        var record = System.Text.Json.JsonSerializer.Serialize(
            ServiceNowChannel.Record(Sample, "Platform Team"));

        Assert.Contains("trace-42", record);
        Assert.Contains("\"urgency\":\"1\"", record);
        Assert.Contains("Platform Team", record);
    }

    /// <summary>The channels under test never reach the network here; only their shapes matter.</summary>
    private sealed class HttpFactoryStub : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }
}
