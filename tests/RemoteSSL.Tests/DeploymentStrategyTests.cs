using System.Reflection;
using RemoteSSL.Application.Deployments;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Tests;

/// <summary>
/// Strategy shape and HA ordering of design doc §21.4/§14.3. The orchestrator keeps these
/// private, so they are reached through reflection rather than being widened for tests.
/// </summary>
public class DeploymentStrategyTests
{
    private static (int MaxConcurrency, bool StopOnFailure, bool ManualContinuation) Resolve(
        string strategy, int maxConcurrency = 0)
    {
        var method = typeof(DeploymentService).GetMethod("ResolveStrategy",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        return ((int, bool, bool))method.Invoke(null, [strategy, maxConcurrency])!;
    }

    private static int HaRank(string? role)
    {
        var method = typeof(DeploymentService).GetMethod("HaRank", BindingFlags.NonPublic | BindingFlags.Static)!;
        var jt = new DeploymentJobTarget
        {
            DeploymentBinding = new DeploymentBinding
            {
                CertificateStore = new CertificateStore { Target = new Target { HaRole = role } }
            }
        };
        return (int)method.Invoke(null, [jt])!;
    }

    [Fact]
    public void Sequential_runs_one_at_a_time_and_stops_on_failure()
    {
        Assert.Equal((1, true, false), Resolve("sequential"));
    }

    [Fact]
    public void All_at_once_has_no_concurrency_limit_and_does_not_stop()
    {
        Assert.Equal((0, false, false), Resolve("all-at-once"));
    }

    [Fact]
    public void Wave_defaults_to_two_at_a_time()
    {
        Assert.Equal((2, true, false), Resolve("wave"));
        Assert.Equal((5, true, false), Resolve("wave", 5));
    }

    [Fact]
    public void Canary_and_manual_pause_between_waves()
    {
        Assert.True(Resolve("canary").ManualContinuation);
        Assert.True(Resolve("manual").ManualContinuation);
        Assert.Equal(1, Resolve("canary").MaxConcurrency);
    }

    [Fact]
    public void Ha_pair_is_strictly_one_at_a_time()
    {
        var shape = Resolve("ha-pair", 4);
        Assert.Equal(1, shape.MaxConcurrency);
        Assert.True(shape.StopOnFailure);
        Assert.False(shape.ManualContinuation);
    }

    [Fact]
    public void Standby_members_deploy_before_unpaired_and_active_ones()
    {
        Assert.True(HaRank("standby") < HaRank(null));
        Assert.True(HaRank(null) < HaRank("active"));
        Assert.Equal(HaRank("STANDBY"), HaRank("standby"));
    }
}
