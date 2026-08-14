using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Deployments;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Watches for work stranded on runners that stopped answering (design doc §34.2) and hands it to
/// another runner in the same affinity group. Leader-elected: two nodes reclaiming the same job
/// would be the double-dispatch this exists to prevent.
/// </summary>
public class RunnerFailoverService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    PostgresLeaderLock leaderLock,
    ILogger<RunnerFailoverService> logger) : BackgroundService
{
    private const long LockKey = 0x5253464F; // "RSFO" — runner failover leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(configuration.GetValue("Runner:FailoverIntervalSeconds", 30));
        var maxAttempts = configuration.GetValue("Runner:MaxJobAttempts", 3);

        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, async () =>
                {
                    var (scope, tenancy) = BackgroundScope.CreateCrossTenant(scopeFactory);
                    using var backgroundScope = scope;
                    using var backgroundTenancy = tenancy;

                    var failover = scope.ServiceProvider.GetRequiredService<RunnerFailover>();
                    var result = await failover.ReclaimAsync(DateTimeOffset.UtcNow, maxAttempts, stoppingToken);

                    // The events these produce are the notification; the log line is for the node's
                    // own operator, so it only speaks when something actually moved.
                    if (result.Requeued > 0 || result.Failed > 0)
                        logger.LogInformation(
                            "Runner failover: {Requeued} job(s) requeued, {Failed} abandoned",
                            result.Requeued, result.Failed);

                    // The outbox rows written above only exist once this commits (§28.2).
                    await scope.ServiceProvider.GetRequiredService<IRemoteSslDbContext>()
                        .SaveChangesAsync(stoppingToken);
                }, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Runner failover pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
