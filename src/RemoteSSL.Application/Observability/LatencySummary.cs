namespace RemoteSSL.Application.Observability;

/// <summary>Percentile view of a latency metric over a window (§32.1).</summary>
public sealed record LatencySummary(int Count, double? P50Ms, double? P95Ms, double? MaxMs)
{
    public static readonly LatencySummary Empty = new(0, null, null, null);

    /// <summary>
    /// Nearest-rank percentiles over the given samples. Kept free of EF so it is
    /// unit-testable and usable on both the dashboard and the /metrics endpoint.
    /// </summary>
    public static LatencySummary From(IEnumerable<double> samples)
    {
        var ordered = samples.OrderBy(v => v).ToArray();
        if (ordered.Length == 0) return Empty;
        return new LatencySummary(
            ordered.Length,
            Math.Round(Percentile(ordered, 0.50), 1),
            Math.Round(Percentile(ordered, 0.95), 1),
            Math.Round(ordered[^1], 1));
    }

    private static double Percentile(double[] ordered, double p)
    {
        // Nearest-rank: rank = ceil(p * N), clamped into the array.
        var rank = (int)Math.Ceiling(p * ordered.Length);
        return ordered[Math.Clamp(rank - 1, 0, ordered.Length - 1)];
    }
}

/// <summary>One day of a latency trend line (§32.1 dashboard history).</summary>
public sealed record LatencyTrendPoint(DateOnly Day, int Count, double? P50Ms, double? P95Ms);
