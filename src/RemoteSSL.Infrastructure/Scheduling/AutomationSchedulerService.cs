using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Automation;
using RemoteSSL.Domain;
using RemoteSSL.Application.Events;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>Periodic automation tick: CA polling, renewals, windowed execution, drift, runner health.</summary>
public class AutomationSchedulerService(
    IServiceScopeFactory scopeFactory, IConfiguration configuration,
    PostgresLeaderLock leaderLock, ILogger<AutomationSchedulerService> logger) : BackgroundService
{
    private const long LockKey = 0x52535341; // "RSSA" — automation scheduler leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tick = TimeSpan.FromSeconds(configuration.GetValue("Automation:TickSeconds", 60));
        var offlineAfter = TimeSpan.FromSeconds(configuration.GetValue("Automation:RunnerOfflineSeconds", 120));
        using var timer = new PeriodicTimer(tick);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, async () =>
                {
                    await using var scope = scopeFactory.CreateAsyncScope();
                    await scope.ServiceProvider.GetRequiredService<AutomationService>().TickAsync(stoppingToken);

                    // Runner health (design doc §29.1). Each runner that falls silent gets its own
                    // event (§28.1 RunnerOffline) — a silent runner is why a deployment stalls.
                    var db = scope.ServiceProvider.GetRequiredService<RemoteSslDbContext>();
                    var cutoff = DateTimeOffset.UtcNow - offlineAfter;
                    var goneQuiet = await db.Runners
                        .Where(r => r.Status == RunnerStatus.Online && (r.LastHeartbeatAt == null || r.LastHeartbeatAt < cutoff))
                        .ToListAsync(stoppingToken);
                    if (goneQuiet.Count > 0)
                    {
                        var notifier = scope.ServiceProvider.GetRequiredService<INotificationSink>();
                        foreach (var runner in goneQuiet)
                        {
                            runner.Status = RunnerStatus.Offline;
                            notifier.Notify(DomainEvents.RunnerOffline, new
                            {
                                runnerId = runner.Id,
                                runner.Name,
                                runner.Segment,
                                lastHeartbeatAt = runner.LastHeartbeatAt
                            });
                        }
                        await db.SaveChangesAsync(stoppingToken);
                    }
                }, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogError(ex, "Automation tick failed");
            }
            if (!await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false)) break;
        }
    }
}
