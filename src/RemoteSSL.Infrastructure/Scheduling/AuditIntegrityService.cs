using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Events;
using RemoteSSL.Application.Observability;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Keeps the audit log's integrity machinery running (design doc §25.3): seal new rows into the
/// hash chain, copy sealed rows to the external write-once store, verify the chain periodically,
/// and purge only what retention allows. Leader-elected, because sealing depends on a single
/// writer walking rows in order (§34.1).
/// </summary>
public class AuditIntegrityService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    PostgresLeaderLock leaderLock,
    AuditPipelineHealth health,
    ILogger<AuditIntegrityService> logger) : BackgroundService
{
    private const long LockKey = 0x52534149; // "RSAI" — audit integrity leader lock

    private DateTimeOffset _lastVerify = DateTimeOffset.MinValue;
    private DateTimeOffset _lastRetention = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(configuration.GetValue("Audit:SealIntervalSeconds", 30));
        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, () => PassAsync(stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Audit integrity pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task PassAsync(CancellationToken ct)
    {
        var (scope, tenancy) = BackgroundScope.CreateCrossTenant(scopeFactory);
        using var backgroundScope = scope;
        using var backgroundTenancy = tenancy;
        var chain = scope.ServiceProvider.GetRequiredService<AuditChain>();
        var archive = scope.ServiceProvider.GetRequiredService<AuditArchive>();

        var sealedRows = await chain.SealAsync(configuration.GetValue("Audit:SealBatchSize", 500), ct);
        if (sealedRows > 0) logger.LogDebug("Sealed {Count} audit row(s) into the hash chain", sealedRows);

        // §25.3 external copy. Without an object store there is nowhere to put it, and the SIEM
        // forward is then the only outside copy — which is why that is the documented alternative.
        if (archive.Available)
        {
            var result = await archive.ArchiveBatchAsync(configuration.GetValue("Audit:ArchiveBatchSize", 500), ct);
            if (result.Rows > 0)
                logger.LogInformation("Archived audit rows {From}-{To} to {Key}",
                    result.FromSequence, result.ToSequence, result.Key);
        }

        var now = DateTimeOffset.UtcNow;

        if (now - _lastVerify > TimeSpan.FromHours(configuration.GetValue("Audit:VerifyIntervalHours", 6)))
        {
            _lastVerify = now;
            var status = await chain.VerifyAsync(ct);
            if (!status.Intact)
            {
                // A broken chain is not a background-log-warning matter: it means the compliance
                // record can no longer be trusted, so it goes down the same path as a failed audit
                // write and reaches the dashboard alarm.
                logger.LogError("Audit chain verification failed at sequence {Sequence}: {Detail}",
                    status.FirstBrokenSequence, status.Detail);
                health.RecordFailure("audit.chain",
                    new InvalidOperationException(status.Detail ?? "audit chain verification failed"));

                var notifier = scope.ServiceProvider.GetRequiredService<INotificationSink>();
                var db = scope.ServiceProvider.GetRequiredService<IRemoteSslDbContext>();
                notifier.Notify(DomainEvents.AuditChainBroken, new
                {
                    firstBrokenSequence = status.FirstBrokenSequence,
                    detail = status.Detail,
                    sealedRows = status.Sealed
                });
                await db.SaveChangesAsync(ct);
            }
        }

        var retentionDays = configuration.GetValue("Audit:RetentionDays", 0);
        if (retentionDays > 0 && now - _lastRetention > TimeSpan.FromHours(12))
        {
            _lastRetention = now;
            var purged = await PurgeAsync(scope, now.AddDays(-retentionDays), archive.Available, ct);
            if (purged > 0) logger.LogInformation("Purged {Count} audit row(s) past retention", purged);
        }
    }

    /// <summary>
    /// Runs the retention purge inside a transaction that declares itself to the append-only
    /// trigger. Without that declaration the database refuses the delete — which is the point:
    /// this is the only code path allowed to remove an audit row (§25.3).
    /// </summary>
    private static async Task<int> PurgeAsync(
        IServiceScope scope, DateTimeOffset olderThan, bool requireArchived, CancellationToken ct)
    {
        var retention = scope.ServiceProvider.GetRequiredService<AuditRetention>();
        var db = scope.ServiceProvider.GetRequiredService<Persistence.RemoteSslDbContext>();
        if (!db.Database.IsRelational())
            return await retention.PurgeAsync(olderThan, requireArchived, 500, ct);

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.Database.ExecuteSqlRawAsync("SET LOCAL remotessl.audit_retention = 'on'", ct);
        var purged = await retention.PurgeAsync(olderThan, requireArchived, 500, ct);
        await transaction.CommitAsync(ct);
        return purged;
    }
}
