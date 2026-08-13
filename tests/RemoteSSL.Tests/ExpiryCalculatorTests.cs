using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;

namespace RemoteSSL.Tests;

public class ExpiryCalculatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 13, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(42, CertificateHealthStatus.Healthy)]
    [InlineData(31, CertificateHealthStatus.Healthy)]
    [InlineData(30, CertificateHealthStatus.ExpiringSoon)]
    [InlineData(17, CertificateHealthStatus.ExpiringSoon)]
    [InlineData(7, CertificateHealthStatus.Critical)]
    [InlineData(1, CertificateHealthStatus.Critical)]
    [InlineData(0, CertificateHealthStatus.Critical)]
    [InlineData(-1, CertificateHealthStatus.Expired)]
    public void HealthFor_maps_days_left_to_status(int daysLeft, CertificateHealthStatus expected)
    {
        var notAfter = Now.AddDays(daysLeft).AddHours(1);
        Assert.Equal(expected, ExpiryCalculator.HealthFor(notAfter, Now));
    }

    [Fact]
    public void CrossedThresholds_first_observation_emits_all_passed_thresholds()
    {
        var crossed = ExpiryCalculator.CrossedThresholds(previousDaysLeft: null, currentDaysLeft: 25);
        Assert.Equal([90, 60, 45, 30], crossed);
    }

    [Fact]
    public void CrossedThresholds_emits_each_threshold_exactly_once()
    {
        var crossed = ExpiryCalculator.CrossedThresholds(previousDaysLeft: 25, currentDaysLeft: 12);
        Assert.Equal([15], crossed);

        var none = ExpiryCalculator.CrossedThresholds(previousDaysLeft: 12, currentDaysLeft: 12);
        Assert.Empty(none);
    }
}
