namespace RemoteSSL.Domain.Entities;

/// <summary>
/// Time-series sample for the operational metrics of design doc §32.1 that need
/// history rather than a running counter (probe_latency, ca_request_latency).
/// Rows are pruned by the retention job; they carry no secret material.
/// </summary>
public class MetricSample
{
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    /// <summary>Metric name as published on /metrics, e.g. "probe_latency" or "ca_request_latency".</summary>
    public string Metric { get; set; } = string.Empty;
    /// <summary>Observed duration in milliseconds.</summary>
    public double ValueMs { get; set; }
    /// <summary>Dimension of the sample: "host:port" for probes, "connector.operation" for CA calls.</summary>
    public string? Label { get; set; }
    /// <summary>Whether the measured operation itself succeeded (failures skew latency otherwise).</summary>
    public bool Success { get; set; }
    /// <summary>Trace correlation id of the operation that produced the sample (§32.2).</summary>
    public string? CorrelationId { get; set; }
}
