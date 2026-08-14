using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Events;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Drains the transactional outbox (design doc §28.2). Runs on every node but takes the leader
/// lock for a pass, so an event is published once even with several API instances up. Dispatched
/// messages are pruned after a retention window; failed ones are kept as evidence.
/// </summary>
public class OutboxDispatcherService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    PostgresLeaderLock leaderLock,
    ILogger<OutboxDispatcherService> logger) : BackgroundService
{
    private const long LockKey = 0x52534F42; // "RSOB" — outbox leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(configuration.GetValue("Notifications:Outbox:IntervalSeconds", 5));
        var batchSize = configuration.GetValue("Notifications:Outbox:BatchSize", 50);
        var retentionDays = configuration.GetValue("Notifications:Outbox:RetentionDays", 14);
        var lastPrune = DateTimeOffset.MinValue;

        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, async () =>
                {
                    using var scope = scopeFactory.CreateScope();
                    var dispatcher = scope.ServiceProvider.GetRequiredService<OutboxDispatcher>();
                    await dispatcher.DispatchBatchAsync(DateTimeOffset.UtcNow, batchSize, stoppingToken);

                    // Pruning is cheap but pointless to run every few seconds.
                    if (DateTimeOffset.UtcNow - lastPrune > TimeSpan.FromHours(1))
                    {
                        lastPrune = DateTimeOffset.UtcNow;
                        await dispatcher.PruneAsync(DateTimeOffset.UtcNow.AddDays(-retentionDays), stoppingToken);
                    }
                }, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Outbox dispatch pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
