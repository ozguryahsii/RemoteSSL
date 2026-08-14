using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Prunes latency samples past their retention window. Metric history is operational
/// telemetry, not the audit trail — unlike audit rows (§25.3) it may be deleted freely.
/// Leader-elected so a multi-node control plane prunes once (§34.1).
/// </summary>
public class MetricsRetentionService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    PostgresLeaderLock leaderLock,
    ILogger<MetricsRetentionService> logger) : BackgroundService
{
    private const long LockKey = 0x52534D52; // "RSMR" — metrics retention leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var retentionDays = configuration.GetValue("Observability:MetricRetentionDays", 30);
        using var timer = new PeriodicTimer(TimeSpan.FromHours(6));
        do
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, () => PruneAsync(retentionDays, stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Metric retention pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task PruneAsync(int retentionDays, CancellationToken ct)
    {
        var (scope, tenancy) = BackgroundScope.CreateCrossTenant(scopeFactory);
        using var backgroundScope = scope;
        using var backgroundTenancy = tenancy;
        var db = scope.ServiceProvider.GetRequiredService<RemoteSslDbContext>();
        var cutoff = DateTimeOffset.UtcNow.AddDays(-retentionDays);
        var removed = await db.MetricSamples.Where(s => s.Timestamp < cutoff).ExecuteDeleteAsync(ct);
        if (removed > 0) logger.LogInformation("Pruned {Count} metric sample(s) older than {Days}d", removed, retentionDays);
    }
}
