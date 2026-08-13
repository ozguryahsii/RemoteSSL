using RemoteSSL.Domain;

namespace RemoteSSL.Application.Monitoring;

public static class ExpiryCalculator
{
    /// <summary>Alert thresholds in days-to-expiry, per FR-002 (T-90 … T-1).</summary>
    public static readonly int[] AlertThresholdDays = [90, 60, 45, 30, 15, 7, 1];

    public static int DaysUntilExpiry(DateTimeOffset notAfter, DateTimeOffset now)
        => (int)Math.Floor((notAfter - now).TotalDays);

    public static CertificateHealthStatus HealthFor(DateTimeOffset notAfter, DateTimeOffset now)
    {
        var days = DaysUntilExpiry(notAfter, now);
        return days switch
        {
            < 0 => CertificateHealthStatus.Expired,
            <= 7 => CertificateHealthStatus.Critical,
            <= 30 => CertificateHealthStatus.ExpiringSoon,
            _ => CertificateHealthStatus.Healthy
        };
    }

    /// <summary>
    /// Thresholds newly crossed between two observations — each is emitted exactly
    /// once as the remaining lifetime passes it.
    /// </summary>
    public static IReadOnlyList<int> CrossedThresholds(int? previousDaysLeft, int currentDaysLeft)
        => AlertThresholdDays
            .Where(t => currentDaysLeft <= t && (previousDaysLeft is null || previousDaysLeft > t))
            .ToArray();
}
