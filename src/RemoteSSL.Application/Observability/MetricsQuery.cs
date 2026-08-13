using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;

namespace RemoteSSL.Application.Observability;

/// <summary>Reads the stored latency samples back as the §32.1 dashboard figures.</summary>
public class MetricsQuery(IRemoteSslDbContext db)
{
    /// <summary>Percentiles over the window; failed operations are excluded so timeouts don't dominate.</summary>
    public async Task<LatencySummary> SummaryAsync(string metric, TimeSpan window, CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow - window;
        var values = await db.MetricSamples.AsNoTracking()
            .Where(s => s.Metric == metric && s.Timestamp >= cutoff && s.Success)
            .Select(s => s.ValueMs)
            .ToListAsync(ct);
        return LatencySummary.From(values);
    }

    /// <summary>Daily p50/p95 for the trend line, oldest day first.</summary>
    public async Task<IReadOnlyList<LatencyTrendPoint>> TrendAsync(string metric, int days, CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow.Date.AddDays(-(days - 1));
        var samples = await db.MetricSamples.AsNoTracking()
            .Where(s => s.Metric == metric && s.Timestamp >= cutoff && s.Success)
            .Select(s => new { s.Timestamp, s.ValueMs })
            .ToListAsync(ct);

        return samples
            .GroupBy(s => DateOnly.FromDateTime(s.Timestamp.UtcDateTime))
            .OrderBy(g => g.Key)
            .Select(g =>
            {
                var summary = LatencySummary.From(g.Select(x => x.ValueMs));
                return new LatencyTrendPoint(g.Key, summary.Count, summary.P50Ms, summary.P95Ms);
            })
            .ToList();
    }
}
