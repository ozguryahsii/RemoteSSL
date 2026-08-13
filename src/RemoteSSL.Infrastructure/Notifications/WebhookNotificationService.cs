using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace RemoteSSL.Infrastructure.Notifications;

/// <summary>
/// Fire-and-forget webhook notifications (design doc §33): failures are logged and
/// alarmed but never affect the operation that triggered them. Teams/e-mail/SIEM
/// integrations plug in behind the same shape later.
/// </summary>
public class WebhookNotificationService(
    IHttpClientFactory httpFactory, IConfiguration config, ILogger<WebhookNotificationService> logger)
{
    public void Notify(string eventType, object payload)
    {
        var url = config["Notifications:WebhookUrl"];
        if (string.IsNullOrEmpty(url)) return;
        _ = Task.Run(async () =>
        {
            try
            {
                using var http = httpFactory.CreateClient("webhook");
                http.Timeout = TimeSpan.FromSeconds(10);
                await http.PostAsJsonAsync(url, new { @event = eventType, timestamp = DateTimeOffset.UtcNow, data = payload });
            }
            catch (Exception ex)
            {
                logger.LogWarning("Webhook notification '{Event}' failed: {Error}", eventType, ex.Message);
            }
        });
    }
}
