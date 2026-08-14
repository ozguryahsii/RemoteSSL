using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// In-process probe scheduler: every tick, probes enabled monitors whose interval has
/// elapsed, with bounded parallelism. Moves to the distributed job engine in F2;
/// leader election arrives with multi-node control plane (design doc §34.1).
/// </summary>
public class ProbeSchedulerService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    PostgresLeaderLock leaderLock,
    ILogger<ProbeSchedulerService> logger) : BackgroundService
{
    private const long LockKey = 0x52535350; // "RSSP" — probe scheduler leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tick = TimeSpan.FromSeconds(configuration.GetValue("Monitoring:SchedulerTickSeconds", 60));
        var defaultInterval = configuration.GetValue("Monitoring:DefaultProbeIntervalMinutes", 60);
        var maxParallel = configuration.GetValue("Monitoring:MaxParallelProbes", 8);

        logger.LogInformation("Probe scheduler started (tick {Tick}s, default interval {Interval}m)",
            tick.TotalSeconds, defaultInterval);

        using var timer = new PeriodicTimer(tick);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey,
                    () => RunDueProbesAsync(defaultInterval, maxParallel, stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Probe scheduler tick failed");
            }

            if (!await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false)) break;
        }
    }

    private async Task RunDueProbesAsync(int defaultIntervalMinutes, int maxParallel, CancellationToken ct)
    {
        // NFR-004: at ten thousand endpoints the naive shape — load every due monitor, then probe
        // them all — holds the whole set in memory and lets one tick run for as long as the slowest
        // probe times out. Two things prevent that. The due set is computed in the database and
        // capped per tick, so memory is bounded by the batch and not by the inventory; and what
        // does not fit this tick is simply first in line for the next one, because the ordering is
        // oldest-probe-first.
        var batchSize = configuration.GetValue("Monitoring:MaxProbesPerTick", 500);

        List<Guid> dueIds;
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemoteSslDbContext>();
            // Probing serves every tenant; the filter must not hide another tenant's monitors.
            using var tenancy = scope.ServiceProvider
                .GetRequiredService<RemoteSSL.Application.Abstractions.ITenantContext>().EnterCrossTenant();

            var now = DateTimeOffset.UtcNow;
            var due = await db.MonitorEndpoints
                .Where(m => m.Enabled)
                .Where(m => m.LastProbeAt == null
                            || m.LastProbeAt < now.AddMinutes(-(m.ProbeIntervalMinutes ?? defaultIntervalMinutes)))
                // Never probed first, then longest-waiting: no monitor can be starved by a
                // permanently full batch.
                .OrderBy(m => m.LastProbeAt ?? DateTimeOffset.MinValue)
                .Take(batchSize)
                .ToListAsync(ct);

            // Every monitor with an internal vantage also gets a runner-side probe;
            // the external (control-plane) probe still runs unless explicitly disabled.
            foreach (var pinned in due.Where(m => m.RunnerId != null))
                await MonitorProbeService.QueueRunnerProbeAsync(db, pinned, ct);
            await db.SaveChangesAsync(ct);

            dueIds = due.Where(m => m.ExternalProbeEnabled).Select(m => m.Id).ToList();

            if (due.Count == batchSize)
                logger.LogInformation(
                    "Probe batch is full at {Batch}; the remaining due monitors go to the next tick",
                    batchSize);
        }

        if (dueIds.Count == 0) return;
        logger.LogInformation("Probing {Count} due monitor(s)", dueIds.Count);

        await Parallel.ForEachAsync(dueIds,
            new ParallelOptions { MaxDegreeOfParallelism = maxParallel, CancellationToken = ct },
            async (monitorId, token) =>
            {
                var (scope, tenancy) = BackgroundScope.CreateCrossTenant(scopeFactory);
                using var probeScope = scope;
                using var probeTenancy = tenancy;
                var service = scope.ServiceProvider.GetRequiredService<MonitorProbeService>();
                try
                {
                    await service.ProbeAsync(monitorId, token);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Scheduled probe failed for monitor {MonitorId}", monitorId);
                }
            });
    }
}
