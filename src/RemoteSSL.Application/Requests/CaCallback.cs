using System.Text.Json;

namespace RemoteSSL.Application.Requests;

/// <summary>
/// Reading a CA's callback body (ADR-009). Nothing about issuance is taken from here — the only
/// thing extracted is which request the callback is about, so the platform knows what to re-poll.
/// </summary>
public static class CaCallback
{
    /// <summary>The names vendors use for their own request id, in the order they are tried.</summary>
    private static readonly string[] IdFields =
        ["requestId", "request_id", "orderId", "order_id", "id", "sslId"];

    /// <summary>
    /// The provider's request id, if the callback mentions one. Returning null is not a failure:
    /// it simply means every open request on that connector is re-checked instead of one.
    /// </summary>
    public static string? ExtractProviderRequestId(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            var json = JsonDocument.Parse(body).RootElement;
            foreach (var name in IdFields)
                if (json.TryGetProperty(name, out var value))
                    return value.ToString();
        }
        catch (JsonException)
        {
            // A non-JSON callback is fine; it just carries no id to narrow by.
        }
        return null;
    }
}
