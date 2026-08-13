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
    ILogger<ProbeSchedulerService> logger) : BackgroundService
{
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
                await RunDueProbesAsync(defaultInterval, maxParallel, stoppingToken);
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
        List<Guid> dueIds;
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemoteSslDbContext>();
            var now = DateTimeOffset.UtcNow;
            dueIds = await db.MonitorEndpoints
                .Where(m => m.Enabled)
                .Where(m => m.LastProbeAt == null
                            || m.LastProbeAt < now.AddMinutes(-(m.ProbeIntervalMinutes ?? defaultIntervalMinutes)))
                .Select(m => m.Id)
                .ToListAsync(ct);
        }

        if (dueIds.Count == 0) return;
        logger.LogInformation("Probing {Count} due monitor(s)", dueIds.Count);

        await Parallel.ForEachAsync(dueIds,
            new ParallelOptions { MaxDegreeOfParallelism = maxParallel, CancellationToken = ct },
            async (monitorId, token) =>
            {
                await using var scope = scopeFactory.CreateAsyncScope();
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
