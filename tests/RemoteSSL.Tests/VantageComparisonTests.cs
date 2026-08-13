using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;

namespace RemoteSSL.Tests;

public class VantageComparisonTests
{
    private static readonly DateTimeOffset Soon = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Later = new(2027, 9, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Same_certificate_on_both_sides_is_a_match()
    {
        var (verdict, _) = VantageComparison.Compare(true,
            ProbeStatus.Success, "AABB", Later,
            ProbeStatus.Success, "AABB", Later);
        Assert.Equal(VantageVerdict.Match, verdict);
    }

    [Fact]
    public void Renewed_outside_but_not_inside_flags_the_internal_side_as_stale()
    {
        var (verdict, detail) = VantageComparison.Compare(true,
            ProbeStatus.Success, "NEW", Later,   // published endpoint already renewed
            ProbeStatus.Success, "OLD", Soon);   // application server still on the old cert
        Assert.Equal(VantageVerdict.Mismatch, verdict);
        Assert.Contains("internal (application server)", detail);
    }

    [Fact]
    public void Renewed_inside_but_not_outside_flags_the_external_side_as_stale()
    {
        var (verdict, detail) = VantageComparison.Compare(true,
            ProbeStatus.Success, "OLD", Soon,
            ProbeStatus.Success, "NEW", Later);
        Assert.Equal(VantageVerdict.Mismatch, verdict);
        Assert.Contains("external (published endpoint)", detail);
    }

    [Fact]
    public void Internal_only_service_reports_internal_only()
    {
        var (verdict, _) = VantageComparison.Compare(true,
            ProbeStatus.DnsResolutionFailed, null, null,
            ProbeStatus.Success, "AABB", Later);
        Assert.Equal(VantageVerdict.InternalOnly, verdict);
    }

    [Fact]
    public void Unreachable_application_server_reports_external_only()
    {
        var (verdict, _) = VantageComparison.Compare(true,
            ProbeStatus.Success, "AABB", Later,
            ProbeStatus.ConnectionFailed, null, null);
        Assert.Equal(VantageVerdict.ExternalOnly, verdict);
    }

    [Fact]
    public void Without_a_runner_there_is_nothing_to_compare()
    {
        var (verdict, _) = VantageComparison.Compare(false,
            ProbeStatus.Success, "AABB", Later,
            ProbeStatus.NeverProbed, null, null);
        Assert.Equal(VantageVerdict.NotConfigured, verdict);
    }

    [Fact]
    public void Both_sides_down_reports_both_unreachable()
    {
        var (verdict, _) = VantageComparison.Compare(true,
            ProbeStatus.Timeout, null, null,
            ProbeStatus.ConnectionFailed, null, null);
        Assert.Equal(VantageVerdict.BothUnreachable, verdict);
    }
}
