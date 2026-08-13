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
        var cutoff = WindowStartUtc(DateTimeOffset.UtcNow, days);
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

    /// <summary>
    /// Midnight UTC of the first day in the window. Built from the parts rather than
    /// DateTimeOffset.Date: that property drops the offset, and converting the result back
    /// re-attaches the server's *local* offset — which PostgreSQL's 'timestamp with time zone'
    /// rejects for anything but UTC, so the query would only fail outside UTC servers.
    /// </summary>
    public static DateTimeOffset WindowStartUtc(DateTimeOffset now, int days)
    {
        var utc = now.ToUniversalTime();
        return new DateTimeOffset(utc.Year, utc.Month, utc.Day, 0, 0, 0, TimeSpan.Zero)
            .AddDays(-(days - 1));
    }
}
