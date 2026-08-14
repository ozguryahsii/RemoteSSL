using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Events;
using RemoteSSL.Application.Security;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Watches credential rotation cadences (design doc §7.3). An overdue credential is flagged and
/// notified, never disabled — a deployment that fails because the platform silently retired a
/// working credential is worse than a stale one. Leader-elected so one node does the pass (§34.1).
/// </summary>
public class SecretRotationService(
    IServiceScopeFactory scopeFactory,
    PostgresLeaderLock leaderLock,
    ILogger<SecretRotationService> logger) : BackgroundService
{
    private const long LockKey = 0x5253524F; // "RSRO" — secret rotation leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, () => ScanAsync(stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Secret rotation pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task ScanAsync(CancellationToken ct)
    {
        var (scope, tenancy) = BackgroundScope.CreateCrossTenant(scopeFactory);
        using var backgroundScope = scope;
        using var backgroundTenancy = tenancy;
        var broker = scope.ServiceProvider.GetRequiredService<SecretBroker>();
        var notifications = scope.ServiceProvider.GetRequiredService<INotificationSink>();
        var db = scope.ServiceProvider.GetRequiredService<IRemoteSslDbContext>();

        var overdue = await broker.MarkOverdueRotationsAsync(DateTimeOffset.UtcNow, ct);
        foreach (var credential in overdue)
        {
            notifications.Notify(DomainEvents.CredentialRotationDue, new
            {
                credential.Id,
                credential.Name,
                Provider = credential.Provider.ToString(),
                credential.LastRotatedAt,
                credential.RotationIntervalDays,
                credential.RotationDueAt
            });
        }
        // The events are outbox rows; they only exist once this commits (§28.2).
        if (overdue.Count > 0) await db.SaveChangesAsync(ct);

        if (overdue.Count > 0)
            logger.LogInformation("{Count} credential(s) are due for rotation", overdue.Count);
    }
}
