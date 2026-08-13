using RemoteSSL.Application.Observability;

namespace RemoteSSL.Tests;

public class LatencySummaryTests
{
    [Fact]
    public void Empty_input_yields_no_percentiles()
    {
        var summary = LatencySummary.From([]);
        Assert.Equal(0, summary.Count);
        Assert.Null(summary.P50Ms);
        Assert.Null(summary.P95Ms);
    }

    [Fact]
    public void Percentiles_use_nearest_rank()
    {
        // 1..100 → p50 is the 50th value, p95 the 95th.
        var summary = LatencySummary.From(Enumerable.Range(1, 100).Select(i => (double)i));
        Assert.Equal(100, summary.Count);
        Assert.Equal(50, summary.P50Ms);
        Assert.Equal(95, summary.P95Ms);
        Assert.Equal(100, summary.MaxMs);
    }

    [Fact]
    public void Single_sample_is_every_percentile()
    {
        var summary = LatencySummary.From([42.5]);
        Assert.Equal(42.5, summary.P50Ms);
        Assert.Equal(42.5, summary.P95Ms);
        Assert.Equal(42.5, summary.MaxMs);
    }

    [Fact]
    public void Unordered_input_is_sorted_before_ranking()
    {
        // Sorted: 10, 20, 30, 900 → nearest rank for p50 over 4 samples is the 2nd value.
        var summary = LatencySummary.From([900, 10, 30, 20]);
        Assert.Equal(20, summary.P50Ms);
        Assert.Equal(900, summary.MaxMs);
    }
}

public class AuditPipelineHealthTests
{
    [Fact]
    public void Failures_inside_the_window_are_reported_newest_first()
    {
        var health = new AuditPipelineHealth();
        health.RecordFailure("certificate.request", new InvalidOperationException("first"));
        health.RecordFailure("deployment.execute", new InvalidOperationException("second"));

        var recent = health.Recent(TimeSpan.FromHours(24));
        Assert.Equal(2, recent.Count);
        Assert.Contains("second", recent[0].Error);
    }

    [Fact]
    public void Older_failures_fall_outside_a_short_window()
    {
        var health = new AuditPipelineHealth();
        health.RecordFailure("certificate.request", new InvalidOperationException("boom"));
        Assert.Empty(health.Recent(TimeSpan.Zero - TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Buffer_is_bounded_so_a_failing_pipeline_cannot_grow_unbounded()
    {
        var health = new AuditPipelineHealth();
        for (var i = 0; i < 200; i++) health.RecordFailure("x", new InvalidOperationException($"e{i}"));
        Assert.Equal(50, health.Recent(TimeSpan.FromHours(1)).Count);
    }
}

public class TraceContextTests
{
    [Fact]
    public void Nested_scopes_inherit_the_outer_correlation_id()
    {
        using var outer = TraceContext.Begin("outer");
        using var inner = TraceContext.Begin("inner");
        Assert.Equal(outer.CorrelationId, inner.CorrelationId);
    }

    [Fact]
    public void An_explicit_id_wins_over_the_inherited_one()
    {
        using var outer = TraceContext.Begin("outer");
        using var inner = TraceContext.Begin("inner", "abc123");
        Assert.Equal("abc123", inner.CorrelationId);
        Assert.NotEqual(outer.CorrelationId, inner.CorrelationId);
    }

    [Fact]
    public void Scope_is_restored_after_dispose()
    {
        Assert.Null(TraceContext.CurrentCorrelationId);
        using (var scope = TraceContext.Begin("op"))
        {
            Assert.Equal(scope.CorrelationId, TraceContext.CurrentCorrelationId);
        }
        Assert.Null(TraceContext.CurrentCorrelationId);
    }
}
