using System.Diagnostics;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Observability;

/// <summary>
/// Records the §32.1 latency metrics. Measurement must never change the outcome of
/// the measured operation, so every failure here is swallowed.
/// </summary>
public class MetricsRecorder(IRemoteSslDbContext db)
{
    public const string ProbeLatency = "probe_latency";
    public const string CaRequestLatency = "ca_request_latency";

    /// <summary>Queues a sample on the unit of work; the caller's SaveChanges persists it.</summary>
    public void Record(string metric, double valueMs, string? label, bool success, string? correlationId = null)
    {
        db.MetricSamples.Add(new MetricSample
        {
            Timestamp = DateTimeOffset.UtcNow,
            Metric = metric,
            ValueMs = valueMs,
            Label = label,
            Success = success,
            CorrelationId = correlationId ?? TraceContext.CurrentCorrelationId
        });
    }

    /// <summary>Persists a sample on its own, for callers outside a unit of work.</summary>
    public async Task RecordAndSaveAsync(string metric, double valueMs, string? label, bool success,
        string? correlationId = null, CancellationToken ct = default)
    {
        try
        {
            Record(metric, valueMs, label, success, correlationId);
            await db.SaveChangesAsync(ct);
        }
        catch
        {
            // Metrics are best-effort: never fail the operation being measured.
        }
    }

    /// <summary>Times an operation and records its latency, propagating the original result or exception.</summary>
    public async Task<T> TimeAsync<T>(string metric, string? label, Func<Task<T>> operation,
        string? correlationId = null, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var ok = false;
        try
        {
            var result = await operation();
            ok = true;
            return result;
        }
        finally
        {
            sw.Stop();
            await RecordAndSaveAsync(metric, sw.Elapsed.TotalMilliseconds, label, ok, correlationId, ct);
        }
    }
}
