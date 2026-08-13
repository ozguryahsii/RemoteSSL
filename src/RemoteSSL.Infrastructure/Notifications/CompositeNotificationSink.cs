using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;
using RemoteSSL.Application.Abstractions;

namespace RemoteSSL.Infrastructure.Notifications;

/// <summary>
/// Fans events out to every configured channel: generic webhook, Microsoft Teams,
/// SMTP e-mail, and the RabbitMQ topic exchange (remotessl.events) for downstream
/// consumers/SIEM. Channels are independent; one failing never blocks another.
/// </summary>
public class CompositeNotificationSink : INotificationSink, IDisposable
{
    private readonly IHttpClientFactory _http;
    private readonly IConfiguration _config;
    private readonly ILogger<CompositeNotificationSink> _logger;
    private readonly Lazy<IConnection?> _rabbit;

    public CompositeNotificationSink(IHttpClientFactory http, IConfiguration config, ILogger<CompositeNotificationSink> logger)
    {
        _http = http;
        _config = config;
        _logger = logger;
        _rabbit = new Lazy<IConnection?>(() =>
        {
            try
            {
                var cs = config.GetConnectionString("RabbitMq");
                if (string.IsNullOrEmpty(cs)) return null;
                var conn = new ConnectionFactory { Uri = new Uri(cs) }.CreateConnection("remotessl-notifications");
                using var ch = conn.CreateModel();
                ch.ExchangeDeclare("remotessl.events", ExchangeType.Topic, durable: true);
                return conn;
            }
            catch (Exception ex)
            {
                logger.LogWarning("RabbitMQ event publishing unavailable: {Error}", ex.Message);
                return null;
            }
        });
    }

    public void Notify(string eventType, object payload)
    {
        var envelope = new { @event = eventType, timestamp = DateTimeOffset.UtcNow, data = payload };
        var json = JsonSerializer.Serialize(envelope);
        _ = Task.Run(() => PublishRabbit(eventType, json));
        _ = Task.Run(() => PostWebhook(_config["Notifications:WebhookUrl"], envelope));
        _ = Task.Run(() => PostTeams(eventType, json));
        _ = Task.Run(() => SendEmail(eventType, json));
    }

    private void PublishRabbit(string eventType, string json)
    {
        try
        {
            var conn = _rabbit.Value;
            if (conn is null) return;
            using var ch = conn.CreateModel();
            var props = ch.CreateBasicProperties();
            props.ContentType = "application/json";
            props.DeliveryMode = 2;
            ch.BasicPublish("remotessl.events", eventType, props, Encoding.UTF8.GetBytes(json));
        }
        catch (Exception ex) { _logger.LogWarning("RabbitMQ publish failed: {Error}", ex.Message); }
    }

    private async Task PostWebhook(string? url, object envelope)
    {
        if (string.IsNullOrEmpty(url)) return;
        try
        {
            using var http = _http.CreateClient("webhook");
            http.Timeout = TimeSpan.FromSeconds(10);
            await http.PostAsJsonAsync(url, envelope);
        }
        catch (Exception ex) { _logger.LogWarning("Webhook failed: {Error}", ex.Message); }
    }

    private async Task PostTeams(string eventType, string json)
    {
        var url = _config["Notifications:TeamsWebhookUrl"];
        if (string.IsNullOrEmpty(url)) return;
        try
        {
            using var http = _http.CreateClient("teams");
            http.Timeout = TimeSpan.FromSeconds(10);
            var card = new
            {
                @type = "MessageCard",
                @context = "http://schema.org/extensions",
                themeColor = eventType.Contains("fail") || eventType.Contains("drift") ? "d63333" : "2eb886",
                summary = $"RemoteSSL: {eventType}",
                title = $"RemoteSSL — {eventType}",
                text = $"```{json}```"
            };
            await http.PostAsJsonAsync(url, card);
        }
        catch (Exception ex) { _logger.LogWarning("Teams webhook failed: {Error}", ex.Message); }
    }

    private void SendEmail(string eventType, string json)
    {
        var host = _config["Notifications:Smtp:Host"];
        var to = _config["Notifications:Smtp:To"];
        if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(to)) return;
        try
        {
            using var client = new System.Net.Mail.SmtpClient(host, _config.GetValue("Notifications:Smtp:Port", 587));
            var user = _config["Notifications:Smtp:Username"];
            if (!string.IsNullOrEmpty(user))
                client.Credentials = new System.Net.NetworkCredential(user, _config["Notifications:Smtp:Password"]);
            client.EnableSsl = _config.GetValue("Notifications:Smtp:UseTls", true);
            client.Send(new System.Net.Mail.MailMessage(
                _config["Notifications:Smtp:From"] ?? "remotessl@localhost", to,
                $"RemoteSSL — {eventType}", json));
        }
        catch (Exception ex) { _logger.LogWarning("SMTP notification failed: {Error}", ex.Message); }
    }

    public void Dispose()
    {
        if (_rabbit.IsValueCreated) _rabbit.Value?.Dispose();
    }
}
