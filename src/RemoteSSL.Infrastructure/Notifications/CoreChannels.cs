using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Configuration;
using RabbitMQ.Client;
using RemoteSSL.Application.Abstractions;

namespace RemoteSSL.Infrastructure.Notifications;

/// <summary>Generic JSON webhook (design doc §33).</summary>
public class WebhookChannel(IHttpClientFactory httpFactory, IConfiguration config) : INotificationChannel
{
    public string Name => "webhook";
    public bool Enabled => !string.IsNullOrWhiteSpace(config["Notifications:WebhookUrl"]);
    public bool Handles(EventEnvelope envelope) => !Application.Events.DomainEvents.IsAuditMirror(envelope.EventType);

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var http = httpFactory.CreateClient("webhook");
        http.Timeout = TimeSpan.FromSeconds(10);
        var response = await http.PostAsJsonAsync(config["Notifications:WebhookUrl"], Body(envelope), ct);
        response.EnsureSuccessStatusCode();
    }

    internal static object Body(EventEnvelope e) => new
    {
        id = e.Id,
        @event = e.EventType,
        schemaVersion = e.SchemaVersion,
        timestamp = e.OccurredAt,
        correlationId = e.CorrelationId,
        data = System.Text.Json.JsonDocument.Parse(e.PayloadJson).RootElement
    };
}

/// <summary>Microsoft Teams incoming webhook (§33).</summary>
public class TeamsChannel(IHttpClientFactory httpFactory, IConfiguration config) : INotificationChannel
{
    public string Name => "teams";
    public bool Enabled => !string.IsNullOrWhiteSpace(config["Notifications:TeamsWebhookUrl"]);
    public bool Handles(EventEnvelope envelope) => !Application.Events.DomainEvents.IsAuditMirror(envelope.EventType);

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var http = httpFactory.CreateClient("teams");
        http.Timeout = TimeSpan.FromSeconds(10);
        var card = new
        {
            type = "MessageCard",
            context = "http://schema.org/extensions",
            themeColor = Application.Events.DomainEvents.SeverityOf(envelope.EventType) <= 4 ? "d63333" : "2eb886",
            summary = $"RemoteSSL: {envelope.EventType}",
            title = $"RemoteSSL — {envelope.EventType}",
            text = $"```{envelope.PayloadJson}```"
        };
        var response = await http.PostAsJsonAsync(config["Notifications:TeamsWebhookUrl"], card, ct);
        response.EnsureSuccessStatusCode();
    }
}

/// <summary>SMTP e-mail (§33).</summary>
public class EmailChannel(IConfiguration config) : INotificationChannel
{
    public string Name => "email";

    public bool Enabled => !string.IsNullOrWhiteSpace(config["Notifications:Smtp:Host"])
                           && !string.IsNullOrWhiteSpace(config["Notifications:Smtp:To"]);

    /// <summary>Mail is for things a person should read, not for every informational event.</summary>
    public bool Handles(EventEnvelope envelope) =>
        !Application.Events.DomainEvents.IsAuditMirror(envelope.EventType)
        && Application.Events.DomainEvents.SeverityOf(envelope.EventType) <= 4;

    public Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        using var client = new System.Net.Mail.SmtpClient(
            config["Notifications:Smtp:Host"], config.GetValue("Notifications:Smtp:Port", 587));
        var user = config["Notifications:Smtp:Username"];
        if (!string.IsNullOrEmpty(user))
            client.Credentials = new System.Net.NetworkCredential(user, config["Notifications:Smtp:Password"]);
        client.EnableSsl = config.GetValue("Notifications:Smtp:UseTls", true);
        client.Send(new System.Net.Mail.MailMessage(
            config["Notifications:Smtp:From"] ?? "remotessl@localhost",
            config["Notifications:Smtp:To"]!,
            $"RemoteSSL — {envelope.EventType}", envelope.PayloadJson));
        return Task.CompletedTask;
    }
}

/// <summary>
/// RabbitMQ topic exchange <c>remotessl.events</c> (§28.2). The event name is the routing key, so
/// consumers bind to what they care about rather than filtering everything.
/// </summary>
public class RabbitMqChannel(IConfiguration config) : INotificationChannel, IDisposable
{
    private readonly object gate = new();
    private IConnection? connection;

    public string Name => "rabbitmq";
    public bool Enabled => !string.IsNullOrWhiteSpace(config.GetConnectionString("RabbitMq"));
    public bool Handles(EventEnvelope envelope) => true;

    /// <summary>
    /// The live connection, opened on demand. Deliberately not cached behind a Lazy: a broker that
    /// was down when the first event arrived must be usable once it comes back, and a Lazy would
    /// remember the failure forever.
    /// </summary>
    private IConnection Connection()
    {
        lock (gate)
        {
            if (connection is { IsOpen: true }) return connection;
            connection?.Dispose();
            var cs = config.GetConnectionString("RabbitMq")
                     ?? throw new InvalidOperationException("RabbitMQ connection string is not configured.");
            connection = new ConnectionFactory { Uri = new Uri(cs) }.CreateConnection("remotessl-events");
            using var declaring = connection.CreateModel();
            declaring.ExchangeDeclare("remotessl.events", ExchangeType.Topic, durable: true);
            return connection;
        }
    }

    public Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        using var channel = Connection().CreateModel();
        var properties = channel.CreateBasicProperties();
        properties.ContentType = "application/json";
        properties.DeliveryMode = 2;
        properties.MessageId = envelope.Id.ToString();
        properties.CorrelationId = envelope.CorrelationId;
        properties.Type = envelope.EventType;
        channel.BasicPublish("remotessl.events", envelope.EventType, properties,
            Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(WebhookChannel.Body(envelope))));
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        lock (gate) connection?.Dispose();
        GC.SuppressFinalize(this);
    }
}
