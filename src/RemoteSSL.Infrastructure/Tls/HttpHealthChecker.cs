using System.Diagnostics;
using RemoteSSL.Application.Monitoring;

namespace RemoteSSL.Infrastructure.Tls;

/// <summary>
/// Performs the optional application reachability check of §2.1. Certificate validity is
/// deliberately not enforced here: the TLS probe already reports chain and hostname problems,
/// and refusing the request would hide whether the application itself is up.
/// </summary>
public class HttpHealthChecker(IHttpClientFactory httpFactory) : IHttpHealthChecker
{
    public const string ClientName = "monitor-health";

    public async Task<HealthCheckResult> CheckAsync(
        string url, int? expectedStatus, TimeSpan timeout, CancellationToken ct)
    {
        var http = httpFactory.CreateClient(ClientName);
        http.Timeout = timeout;

        var stopwatch = Stopwatch.StartNew();
        try
        {
            // HEAD is cheap but often unsupported; fall back to GET without reading the body.
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            stopwatch.Stop();
            return HealthCheckEvaluator.Evaluate(
                (int)response.StatusCode, expectedStatus, (int)stopwatch.ElapsedMilliseconds);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return new HealthCheckResult("Unreachable", $"timed out after {timeout.TotalSeconds:0}s", null);
        }
        catch (HttpRequestException ex)
        {
            return new HealthCheckResult("Unreachable", ex.GetBaseException().Message, null);
        }
    }
}
