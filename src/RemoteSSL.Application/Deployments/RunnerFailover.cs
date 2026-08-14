using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Events;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Deployments;

/// <summary>What one reclaim pass did.</summary>
/// <param name="Requeued">Jobs handed back to the queue for another runner in the same group.</param>
/// <param name="Failed">Jobs that could not be moved and were failed with a reason.</param>
public sealed record ReclaimResult(int Requeued, int Failed);

/// <summary>
/// Recovers work stranded on a runner that stopped answering (design doc §8.2, §34.2).
///
/// The judgement this makes is when <em>not</em> to move a job. A runner that vanished before it
/// touched anything is safe to replace. One that already reported steps has left a target with a
/// backup taken and a change half-applied; running the same job elsewhere could apply it twice, so
/// that job is failed with the reason instead — an operator decides what happens to the target.
///
/// Reassignment stays inside the job's affinity group, because a runner outside it may not be able
/// to reach the target at all.
/// </summary>
public class RunnerFailover(IRemoteSslDbContext db, AuditWriter audit, INotificationSink notifier)
{
    /// <summary>
    /// Reclaims jobs whose lease has expired. A lease outlives a normal job by design: expiry
    /// means the runner is gone, not that the work is slow.
    /// </summary>
    public async Task<ReclaimResult> ReclaimAsync(DateTimeOffset now, int maxAttempts, CancellationToken ct)
    {
        var stranded = await db.RunnerJobs
            .Where(j => (j.Status == "Claimed" || j.Status == "Running")
                        && j.LeaseExpiresAt != null && j.LeaseExpiresAt < now)
            .OrderBy(j => j.ClaimedAt)
            .Take(100)
            .ToListAsync(ct);
        if (stranded.Count == 0) return new ReclaimResult(0, 0);

        // Only a runner that is actually offline strands a job. A busy runner whose lease lapsed
        // but which is still heartbeating keeps its work.
        var runnerIds = stranded.Select(j => j.RunnerId).Where(id => id is not null).Select(id => id!.Value).Distinct();
        var runners = await db.Runners
            .Where(r => runnerIds.Contains(r.Id))
            .ToDictionaryAsync(r => r.Id, ct);

        var requeued = 0;
        var failed = 0;

        foreach (var job in stranded)
        {
            var runner = job.RunnerId is null ? null : runners.GetValueOrDefault(job.RunnerId.Value);
            if (runner is { Status: RunnerStatus.Online })
            {
                // Still alive: extend rather than steal. Losing a job from a working runner would
                // be a self-inflicted double-apply.
                job.LeaseExpiresAt = now.AddMinutes(5);
                continue;
            }

            var blocker = ReassignmentBlocker(job, maxAttempts);
            if (blocker is not null)
            {
                job.Status = "Failed";
                job.CompletedAt = now;
                job.ResultJson = System.Text.Json.JsonSerializer.Serialize(new { error = blocker });
                failed++;

                audit.Append("service:failover", "runner.job-abandoned", "runner_job", job.Id.ToString(),
                    "FAILED", new { runner = runner?.Name, job.JobType, job.Attempts, reason = blocker },
                    job.CorrelationId);
                notifier.Notify(DomainEvents.RunnerJobAbandoned, new
                {
                    jobId = job.Id,
                    job.JobType,
                    runner = runner?.Name,
                    reason = blocker,
                    correlationId = job.CorrelationId
                });
                continue;
            }

            job.ReassignedFromRunnerId = job.RunnerId;
            // Unpinning is what lets another runner claim it; the affinity group still constrains
            // who that can be.
            job.RunnerId = null;
            job.Status = "Queued";
            job.ClaimedAt = null;
            job.LeaseExpiresAt = null;
            requeued++;

            audit.Append("service:failover", "runner.job-reassigned", "runner_job", job.Id.ToString(),
                "REQUEUED", new
                {
                    from = runner?.Name,
                    job.JobType,
                    job.AffinityGroup,
                    job.Attempts
                }, job.CorrelationId);
            notifier.Notify(DomainEvents.RunnerJobReassigned, new
            {
                jobId = job.Id,
                job.JobType,
                from = runner?.Name,
                affinityGroup = job.AffinityGroup,
                correlationId = job.CorrelationId
            });
        }

        await db.SaveChangesAsync(ct);
        return new ReclaimResult(requeued, failed);
    }

    /// <summary>
    /// Why this job may not be handed to another runner, or null when it may. Kept separate so the
    /// rule is testable on its own — it is the part that decides whether a target gets touched
    /// twice.
    /// </summary>
    public static string? ReassignmentBlocker(RunnerJob job, int maxAttempts)
    {
        if (job.NonReassignable)
            return "the job reported progress on its target, so repeating it elsewhere could apply the change twice; "
                   + "check the target and re-deploy deliberately";

        if (job.Attempts >= maxAttempts)
            return $"no runner completed this job after {job.Attempts} attempt(s)";

        return null;
    }

    /// <summary>
    /// Whether a runner may take a job. Affinity is the constraint that matters: a runner outside
    /// the job's group may have no route to the target at all (§34.2).
    /// </summary>
    public static bool CanRun(RunnerNode runner, RunnerJob job)
    {
        if (job.RunnerId is not null && job.RunnerId != runner.Id) return false;
        if (runner.IdentityRevokedAt is not null) return false;
        if (string.IsNullOrWhiteSpace(job.AffinityGroup)) return true;
        return string.Equals(runner.AffinityGroup, job.AffinityGroup, StringComparison.OrdinalIgnoreCase);
    }
}
