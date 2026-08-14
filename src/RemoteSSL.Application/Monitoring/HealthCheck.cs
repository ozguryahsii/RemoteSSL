namespace RemoteSSL.Application.Monitoring;

/// <summary>Outcome of the optional application reachability check (§2.1).</summary>
public sealed record HealthCheckResult(string Status, string? Detail, int? LatencyMs)
{
    public static readonly HealthCheckResult NotConfigured = new("NotConfigured", null, null);
}

/// <summary>
/// Optional HTTP/HTTPS health check on top of the TLS probe. A monitor answers two different
/// questions — is the certificate right, and is the application actually serving — and §2.1
/// keeps them separate: an unhealthy application never turns a good certificate observation
/// into a failed probe.
/// </summary>
public interface IHttpHealthChecker
{
    Task<HealthCheckResult> CheckAsync(string url, int? expectedStatus, TimeSpan timeout, CancellationToken ct);
}

/// <summary>Pure decision so the pass/fail rule is testable without a network.</summary>
public static class HealthCheckEvaluator
{
    /// <summary>
    /// With an expected status configured, only that code is healthy. Without one, any
    /// non-error response (2xx/3xx) counts — a redirect to a login page still proves the
    /// application answered.
    /// </summary>
    public static HealthCheckResult Evaluate(int statusCode, int? expectedStatus, int latencyMs)
    {
        var healthy = expectedStatus is { } expected
            ? statusCode == expected
            : statusCode is >= 200 and < 400;

        return new HealthCheckResult(
            healthy ? "Healthy" : "Unhealthy",
            healthy
                ? $"HTTP {statusCode}"
                : expectedStatus is { } want
                    ? $"HTTP {statusCode}, expected {want}"
                    : $"HTTP {statusCode}",
            latencyMs);
    }
}
