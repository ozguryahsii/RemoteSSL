using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Artifacts;
using RemoteSSL.Domain;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Enforces artifact retention (design doc §31.1, §15.4): expired artifacts are securely
/// deleted, and public artifacts past the retention window go too. Metadata rows survive as
/// evidence — only the content is destroyed. Leader-elected so one node prunes (§34.1).
/// </summary>
public class ArtifactRetentionService(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    PostgresLeaderLock leaderLock,
    ILogger<ArtifactRetentionService> logger) : BackgroundService
{
    private const long LockKey = 0x52534152; // "RSAR" — artifact retention leader lock

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var publicRetentionDays = configuration.GetValue("Storage:PublicArtifactRetentionDays", 365);
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(15));
        do
        {
            try
            {
                await leaderLock.RunAsLeaderAsync(LockKey, () => PruneAsync(publicRetentionDays, stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Artifact retention pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task PruneAsync(int publicRetentionDays, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemoteSslDbContext>();
        var artifacts = scope.ServiceProvider.GetRequiredService<ArtifactService>();
        var now = DateTimeOffset.UtcNow;
        var publicCutoff = now.AddDays(-publicRetentionDays);

        var due = await db.Artifacts
            .Where(a => a.PurgedAt == null
                        && ((a.ExpiresAt != null && a.ExpiresAt <= now)
                            || (a.ExpiresAt == null && a.Sensitivity == ArtifactSensitivity.Public
                                && a.CreatedAt < publicCutoff)))
            .Take(200)
            .ToListAsync(ct);
        if (due.Count == 0) return;

        // Backups written by an adapter live on the target; RemoteSSL cannot delete them from
        // here, so those are reported for cleanup instead of being marked as purged.
        var onTarget = due.Where(a => a.StorageProvider == "target").ToList();
        foreach (var artifact in due.Except(onTarget))
        {
            var reason = artifact.ExpiresAt is not null ? "ttl expired" : $"retention {publicRetentionDays}d";
            await artifacts.PurgeAsync(artifact, reason, ct);
        }
        await db.SaveChangesAsync(ct);

        var purged = due.Count - onTarget.Count;
        if (purged > 0) logger.LogInformation("Securely deleted {Count} artifact(s) past their retention", purged);
        if (onTarget.Count > 0)
            logger.LogInformation(
                "{Count} target-side backup(s) are past their retention window and need cleanup on the target",
                onTarget.Count);
    }
}
