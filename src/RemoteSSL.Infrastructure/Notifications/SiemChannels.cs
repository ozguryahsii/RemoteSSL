using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Events;

namespace RemoteSSL.Infrastructure.Notifications;

/// <summary>
/// Syslog forwarder for SIEM ingestion (design doc §33, §25.3). Speaks RFC 5424 by default and
/// ArcSight CEF when asked, over UDP or TCP. Every domain event goes out, including the audit
/// mirror events — a SIEM's value is in having the whole stream, not a filtered one.
/// Configuration: Integrations:Syslog:{Host,Port,Protocol,Facility,Format,Hostname}.
/// </summary>
public class SyslogChannel(IConfiguration config) : INotificationChannel
{
    private const string AppName = "remotessl";

    public string Name => "syslog";
    public bool Enabled => !string.IsNullOrWhiteSpace(config["Integrations:Syslog:Host"]);
    public bool Handles(EventEnvelope envelope) => true;

    private int Port => config.GetValue("Integrations:Syslog:Port", 514);
    private bool UseTcp => string.Equals(config["Integrations:Syslog:Protocol"], "tcp", StringComparison.OrdinalIgnoreCase);
    private int Facility => config.GetValue("Integrations:Syslog:Facility", 16); // local0
    private bool UseCef => string.Equals(config["Integrations:Syslog:Format"], "cef", StringComparison.OrdinalIgnoreCase);

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var host = config["Integrations:Syslog:Host"]!;
        var bytes = Encoding.UTF8.GetBytes(Format(envelope));

        if (UseTcp)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, Port, ct);
            await using var stream = client.GetStream();
            // Octet-counting framing (RFC 6587) keeps multi-line payloads intact over TCP.
            var framed = Encoding.ASCII.GetBytes($"{bytes.Length} ");
            await stream.WriteAsync(framed, ct);
            await stream.WriteAsync(bytes, ct);
            await stream.FlushAsync(ct);
        }
        else
        {
            using var client = new UdpClient();
            await client.SendAsync(bytes, bytes.Length, host, Port);
        }
    }

    /// <summary>The wire format, chosen by configuration; both carry the same facts.</summary>
    public string Format(EventEnvelope envelope) => UseCef ? Cef(envelope) : Rfc5424(envelope);

    /// <summary>RFC 5424: &lt;PRI&gt;VERSION TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED MSG.</summary>
    public string Rfc5424(EventEnvelope envelope)
    {
        var severity = DomainEvents.SeverityOf(envelope.EventType);
        var priority = Facility * 8 + severity;
        var hostname = config["Integrations:Syslog:Hostname"] ?? Environment.MachineName;
        var structured = $"[remotessl@0 eventId=\"{envelope.Id}\" schema=\"{envelope.SchemaVersion}\" "
                         + $"correlationId=\"{Escape(envelope.CorrelationId ?? "-")}\"]";

        return $"<{priority}>1 {envelope.OccurredAt.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fffZ} "
               + $"{hostname} {AppName} - {envelope.EventType} {structured} {envelope.PayloadJson}";
    }

    /// <summary>ArcSight CEF:0|vendor|product|version|signature|name|severity|extension.</summary>
    public string Cef(EventEnvelope envelope)
    {
        // CEF severity runs 0-10 the other way round from syslog's 0-7.
        var severity = Math.Clamp(10 - DomainEvents.SeverityOf(envelope.EventType), 0, 10);
        var extension = $"eventId={envelope.Id} rt={envelope.OccurredAt.ToUnixTimeMilliseconds()} "
                        + $"cs1Label=correlationId cs1={CefEscape(envelope.CorrelationId ?? "-")} "
                        + $"msg={CefEscape(envelope.PayloadJson)}";
        return $"CEF:0|RemoteSSL|CLM|1.0|{CefEscape(envelope.EventType)}|{CefEscape(envelope.EventType)}"
               + $"|{severity.ToString(CultureInfo.InvariantCulture)}|{extension}";
    }

    private static string Escape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");

    private static string CefEscape(string value) =>
        value.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=").Replace("\n", " ").Replace("\r", " ");
}

/// <summary>
/// Splunk HTTP Event Collector (§33). Sends the envelope as a Splunk event with the source type
/// and index the deployment configures. Configuration: Integrations:Splunk:{Url,Token,Index,SourceType}.
/// </summary>
public class SplunkHecChannel(IHttpClientFactory httpFactory, IConfiguration config) : INotificationChannel
{
    public string Name => "splunk";

    public bool Enabled => !string.IsNullOrWhiteSpace(config["Integrations:Splunk:Url"])
                           && !string.IsNullOrWhiteSpace(config["Integrations:Splunk:Token"]);

    public bool Handles(EventEnvelope envelope) => true;

    public async Task SendAsync(EventEnvelope envelope, CancellationToken ct)
    {
        var http = httpFactory.CreateClient("splunk");
        http.Timeout = TimeSpan.FromSeconds(15);

        using var request = new HttpRequestMessage(HttpMethod.Post,
            config["Integrations:Splunk:Url"]!.TrimEnd('/') + "/services/collector/event")
        {
            Content = JsonContent.Create(new
            {
                time = envelope.OccurredAt.ToUnixTimeMilliseconds() / 1000.0,
                host = Environment.MachineName,
                source = "remotessl",
                sourcetype = config["Integrations:Splunk:SourceType"] ?? "remotessl:event",
                index = config["Integrations:Splunk:Index"],
                @event = WebhookChannel.Body(envelope)
            })
        };
        // Splunk HEC uses its own scheme name, not Bearer.
        request.Headers.Authorization = new AuthenticationHeaderValue("Splunk", config["Integrations:Splunk:Token"]);

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }
}
