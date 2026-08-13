using System.Diagnostics;

namespace RemoteSSL.Application.Observability;

/// <summary>
/// End-to-end correlation for the design doc §32.2 flow
/// (certificate request → CA → deployment job → runner → target).
/// A single id follows the whole chain instead of every service minting a new one;
/// it is also stamped onto the OpenTelemetry activity so traces and audit rows join up.
/// </summary>
public static class TraceContext
{
    /// <summary>Activity source exported over OTLP when tracing is enabled.</summary>
    public static readonly ActivitySource Source = new("RemoteSSL");

    private static readonly AsyncLocal<string?> Current = new();

    /// <summary>Correlation id of the operation in flight, or null when outside a traced scope.</summary>
    public static string? CurrentCorrelationId => Current.Value;

    /// <summary>New id in the canonical format (32 hex chars, same shape as a W3C trace id).</summary>
    public static string NewCorrelationId() => Guid.NewGuid().ToString("N");

    /// <summary>
    /// Enters a traced scope. Reuses the inherited id when the caller does not supply one,
    /// so a renewal that spans request → job → runner keeps a single trace id.
    /// </summary>
    public static Scope Begin(string operation, string? correlationId = null)
    {
        var id = correlationId ?? Current.Value ?? NewCorrelationId();
        var previous = Current.Value;
        Current.Value = id;
        var activity = Source.StartActivity(operation, ActivityKind.Internal);
        activity?.SetTag("remotessl.correlation_id", id);
        return new Scope(id, activity, previous);
    }

    public sealed class Scope(string correlationId, Activity? activity, string? previous) : IDisposable
    {
        public string CorrelationId { get; } = correlationId;

        public void SetTag(string key, object? value) => activity?.SetTag(key, value);

        public void Fail(string error)
        {
            activity?.SetStatus(ActivityStatusCode.Error, error);
        }

        public void Dispose()
        {
            activity?.Dispose();
            Current.Value = previous;
        }
    }
}
