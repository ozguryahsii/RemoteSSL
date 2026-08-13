using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Automation;
using RemoteSSL.Domain;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>Periodic automation tick: CA polling, renewals, windowed execution, drift, runner health.</summary>
public class AutomationSchedulerService(
    IServiceScopeFactory scopeFactory, IConfiguration configuration,
    ILogger<AutomationSchedulerService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tick = TimeSpan.FromSeconds(configuration.GetValue("Automation:TickSeconds", 60));
        var offlineAfter = TimeSpan.FromSeconds(configuration.GetValue("Automation:RunnerOfflineSeconds", 120));
        using var timer = new PeriodicTimer(tick);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<AutomationService>().TickAsync(stoppingToken);

                // Runner health (design doc §29.1)
                var db = scope.ServiceProvider.GetRequiredService<RemoteSslDbContext>();
                var cutoff = DateTimeOffset.UtcNow - offlineAfter;
                await db.Runners
                    .Where(r => r.Status == RunnerStatus.Online && (r.LastHeartbeatAt == null || r.LastHeartbeatAt < cutoff))
                    .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, RunnerStatus.Offline), stoppingToken);
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
