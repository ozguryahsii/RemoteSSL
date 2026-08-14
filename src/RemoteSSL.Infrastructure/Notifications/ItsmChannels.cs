using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Events;

namespace RemoteSSL.Infrastructure.Notifications;

/// <summary>
/// ServiceNow change/ticket integration (design doc §33). Deployment-lifecycle events become
/// records in the configured table — a change request by default, so a certificate rollout leaves
/// the same paper trail as any other production change. Configuration:
/// Integrations:ServiceNow:{BaseUrl,Username,Password,Table,AssignmentGroup}.
/// </summary>
public class ServiceNowChannel(IHttpClientFactory httpFactory, IConfiguration config) : INotificationChannel
{
    public string Name => "servicenow";

    public bool Enabled => !string.IsNullOrWhiteSpace(config["Integrations:ServiceNow:BaseUrl"])
                           && !string.IsNullOrWhiteSpace(config["Integrations:ServiceNow:Username"]);

    /// <summary>Only events that represent a change worth recording; not every probe result.</summary>
    public bool Handles(EventEnvelope envelope) => DomainEvents.ChangeWorthy.Contains(envelope.EventType);

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var table = config["Integrations:ServiceNow:Table"] ?? "change_request";
        var http = httpFactory.CreateClient("servicenow");
        http.Timeout = TimeSpan.FromSeconds(20);

        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"{config["Integrations:ServiceNow:BaseUrl"]!.TrimEnd('/')}/api/now/table/{table}")
        {
            Content = JsonContent.Create(Record(envelope, config["Integrations:ServiceNow:AssignmentGroup"]))
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{config["Integrations:ServiceNow:Username"]}:{config["Integrations:ServiceNow:Password"]}")));

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>The ServiceNow record fields for an event.</summary>
    public static object Record(EventEnvelope envelope, string? assignmentGroup) => new
    {
        short_description = $"RemoteSSL: {envelope.EventType}",
        description = $"Event {envelope.EventType} (id {envelope.Id}, correlation {envelope.CorrelationId ?? "-"})\n\n{envelope.PayloadJson}",
        // ServiceNow's scale runs 1 (high) to 3 (low), the opposite direction to syslog severity.
        urgency = DomainEvents.SeverityOf(envelope.EventType) <= 3 ? "1"
            : DomainEvents.SeverityOf(envelope.EventType) == 4 ? "2" : "3",
        category = "Software",
        correlation_id = envelope.CorrelationId,
        correlation_display = "RemoteSSL",
        assignment_group = assignmentGroup
    };
}

/// <summary>
/// PagerDuty Events API v2 (design doc §33). Only incident-grade events page anyone; the dedup
/// key is the correlation id so a failing deployment updates one incident instead of opening a
/// new one per retry. Configuration: Integrations:PagerDuty:{RoutingKey,Url}.
/// </summary>
public class PagerDutyChannel(IHttpClientFactory httpFactory, IConfiguration config) : INotificationChannel
{
    public string Name => "pagerduty";
    public bool Enabled => !string.IsNullOrWhiteSpace(config["Integrations:PagerDuty:RoutingKey"]);
    public bool Handles(EventEnvelope envelope) => DomainEvents.Incidents.Contains(envelope.EventType);

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var http = httpFactory.CreateClient("pagerduty");
        http.Timeout = TimeSpan.FromSeconds(15);
        var url = config["Integrations:PagerDuty:Url"] ?? "https://events.pagerduty.com/v2/enqueue";

        var response = await http.PostAsJsonAsync(url,
            Payload(envelope, config["Integrations:PagerDuty:RoutingKey"]!), ct);
        response.EnsureSuccessStatusCode();
    }

    public static object Payload(EventEnvelope envelope, string routingKey) => new
    {
        routing_key = routingKey,
        event_action = "trigger",
        dedup_key = $"remotessl:{envelope.EventType}:{envelope.CorrelationId ?? envelope.Id.ToString()}",
        payload = new
        {
            summary = $"RemoteSSL: {envelope.EventType}",
            source = Environment.MachineName,
            severity = DomainEvents.SeverityOf(envelope.EventType) <= 3 ? "error" : "warning",
            timestamp = envelope.OccurredAt.ToUniversalTime().ToString("O"),
            component = "remotessl",
            custom_details = JsonDocument.Parse(envelope.PayloadJson).RootElement
        }
    };
}

/// <summary>
/// Opsgenie alerts (design doc §33), the alternative to PagerDuty. The alias plays the same role
/// as PagerDuty's dedup key, so repeated failures fold into one alert.
/// Configuration: Integrations:Opsgenie:{ApiKey,Url,Team}.
/// </summary>
public class OpsgenieChannel(IHttpClientFactory httpFactory, IConfiguration config) : INotificationChannel
{
    public string Name => "opsgenie";
    public bool Enabled => !string.IsNullOrWhiteSpace(config["Integrations:Opsgenie:ApiKey"]);
    public bool Handles(EventEnvelope envelope) => DomainEvents.Incidents.Contains(envelope.EventType);

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var http = httpFactory.CreateClient("opsgenie");
        http.Timeout = TimeSpan.FromSeconds(15);
        var url = config["Integrations:Opsgenie:Url"] ?? "https://api.opsgenie.com/v2/alerts";

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(Payload(envelope, config["Integrations:Opsgenie:Team"]))
        };
        // Opsgenie uses its own "GenieKey" authorization scheme.
        request.Headers.TryAddWithoutValidation("Authorization", $"GenieKey {config["Integrations:Opsgenie:ApiKey"]}");

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    public static object Payload(EventEnvelope envelope, string? team) => new
    {
        message = $"RemoteSSL: {envelope.EventType}",
        alias = $"remotessl:{envelope.EventType}:{envelope.CorrelationId ?? envelope.Id.ToString()}",
        description = envelope.PayloadJson,
        priority = DomainEvents.SeverityOf(envelope.EventType) <= 3 ? "P1" : "P3",
        source = "RemoteSSL",
        responders = string.IsNullOrWhiteSpace(team)
            ? null
            : new[] { new { name = team, type = "team" } },
        details = new { eventId = envelope.Id.ToString(), correlationId = envelope.CorrelationId }
    };
}
