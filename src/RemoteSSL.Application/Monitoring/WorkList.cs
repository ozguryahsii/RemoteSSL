using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Application.Monitoring;

/// <summary>
/// One thing a person has to do, in the order the purchase cycle really runs.
///
/// Everything RemoteSSL knows is spread over certificates, requests, jobs, targets and runners.
/// Answering "what should I do now" meant opening five screens and holding the sequence in your
/// head — which is the same as not knowing. This is that answer as a list.
/// </summary>
/// <param name="Kind">
/// Which step of the cycle this is: <c>expiring</c>, <c>csr-ready</c>, <c>awaiting-certificate</c>,
/// <c>not-installed</c>, <c>deployment-failed</c>, <c>approval</c>, <c>runner-offline</c>.
/// </param>
/// <param name="Severity">"critical", "warning" or "info" — how soon it stops being optional.</param>
/// <param name="Title">The subject in the operator's words: the certificate, the server.</param>
/// <param name="Detail">What is true about it right now.</param>
/// <param name="Action">What to do next, phrased as the button that does it.</param>
/// <param name="Route">Where that button goes in the UI.</param>
/// <param name="DaysLeft">Days until expiry where the item has a deadline.</param>
public sealed record WorkItem(
    string Kind,
    string Severity,
    string Title,
    string Detail,
    string Action,
    string Route,
    int? DaysLeft = null,
    Guid? CertificateId = null,
    Guid? RequestId = null,
    Guid? JobId = null,
    Guid? TargetId = null);

public class WorkListService(IRemoteSslDbContext db)
{
    /// <summary>
    /// Certificates inside this many days are worth acting on. FR-002 alerts from T-90; the list
    /// starts there too, so what the mail says and what the screen says are the same thing.
    /// </summary>
    public const int HorizonDays = 90;

    public async Task<IReadOnlyList<WorkItem>> BuildAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var items = new List<WorkItem>();

        // Requests in flight, so a certificate already being renewed is not also reported as
        // "expiring, do something" — that double-counting is what makes a list untrustworthy.
        var openRequests = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.State != CertificateRequestState.Active
                        && r.State != CertificateRequestState.Rejected
                        && r.State != CertificateRequestState.FailedBlocked)
            .Select(r => new { r.Id, r.CertificateId, r.CommonName, r.State, r.CreatedAt })
            .ToListAsync(ct);

        var renewing = openRequests.Where(r => r.CertificateId != null)
            .Select(r => r.CertificateId!.Value).ToHashSet();

        // ---- 1. Expiring, and nobody has started a renewal ---------------------------------
        var certificates = await db.Certificates.AsNoTracking()
            .Select(c => new
            {
                c.Id,
                c.CommonName,
                Latest = c.Versions
                    .Where(v => v.Status != CertificateVersionStatus.Superseded
                                && v.Status != CertificateVersionStatus.Revoked)
                    .OrderByDescending(v => v.NotAfter)
                    .Select(v => new { v.Id, v.NotAfter, v.Sha256Thumbprint })
                    .FirstOrDefault(),
                Places = db.DeploymentBindings.Count(b => b.CertificateId == c.Id),
            })
            .ToListAsync(ct);

        foreach (var c in certificates)
        {
            if (c.Latest is null || renewing.Contains(c.Id)) continue;

            var days = ExpiryCalculator.DaysUntilExpiry(c.Latest.NotAfter, now);
            if (days > HorizonDays) continue;

            items.Add(new WorkItem(
                "expiring",
                days <= 15 ? "critical" : days <= 45 ? "warning" : "info",
                c.CommonName,
                days < 0
                    ? $"Expired {-days} day(s) ago" + (c.Places > 0 ? $", still on {c.Places} place(s)" : "")
                    : $"Expires in {days} day(s)" + (c.Places > 0 ? $", on {c.Places} place(s)" : ", not installed anywhere"),
                "Renew it",
                $"/certificates/{c.Id}?renew=1",
                days,
                CertificateId: c.Id));
        }

        // ---- 2. A request that is waiting on the CA, or on us -------------------------------
        foreach (var r in openRequests)
        {
            var waitingDays = (int)(now - r.CreatedAt).TotalDays;
            switch (r.State)
            {
                case CertificateRequestState.CsrGenerated:
                case CertificateRequestState.Validated:
                case CertificateRequestState.Draft:
                    items.Add(new WorkItem(
                        "csr-ready", waitingDays > 3 ? "warning" : "info", r.CommonName,
                        "The CSR is ready to send to the CA.",
                        "Copy the CSR", $"/renewals/{r.Id}", RequestId: r.Id, CertificateId: r.CertificateId));
                    break;

                case CertificateRequestState.SubmittedToCa:
                case CertificateRequestState.PendingIssuance:
                case CertificateRequestState.WaitingForCertificate:
                    items.Add(new WorkItem(
                        "awaiting-certificate", waitingDays > 7 ? "warning" : "info", r.CommonName,
                        $"Sent to the CA {waitingDays} day(s) ago; the issued certificate has not come back yet.",
                        "Upload what the CA sent", $"/renewals/{r.Id}", RequestId: r.Id, CertificateId: r.CertificateId));
                    break;

                case CertificateRequestState.FailedRetryable:
                    items.Add(new WorkItem(
                        "csr-ready", "warning", r.CommonName,
                        "The request failed and can be tried again.",
                        "Open the renewal", $"/renewals/{r.Id}", RequestId: r.Id, CertificateId: r.CertificateId));
                    break;

                case CertificateRequestState.PendingApproval:
                    items.Add(new WorkItem(
                        "approval", "warning", r.CommonName,
                        "This request needs an approver before it can go to the CA.",
                        "Review it", $"/renewals/{r.Id}", RequestId: r.Id, CertificateId: r.CertificateId));
                    break;

                case CertificateRequestState.Issued:
                case CertificateRequestState.ReadyForDeployment:
                    items.Add(new WorkItem(
                        "not-installed", "warning", r.CommonName,
                        "The certificate has come back from the CA and is not installed yet.",
                        "Install it", $"/renewals/{r.Id}", RequestId: r.Id, CertificateId: r.CertificateId));
                    break;
            }
        }

        // ---- 3. A newer certificate exists, but somewhere still serves the old one ----------
        // This is the failure nobody notices: the renewal was bought, installed on three of the
        // ten servers, and the rest quietly expire on the original date.
        var bindings = await db.DeploymentBindings.AsNoTracking()
            .Select(b => new
            {
                b.Id,
                b.CertificateId,
                Target = b.CertificateStore.Target.Name,
                TargetId = b.CertificateStore.Target.Id,
                LastSucceeded = db.DeploymentJobTargets
                    .Where(t => t.DeploymentBindingId == b.Id && t.Status == DeploymentJobStatus.Succeeded)
                    .OrderByDescending(t => t.CompletedAt)
                    .Select(t => (Guid?)t.DeploymentJob.CertificateVersionId)
                    .FirstOrDefault(),
            })
            .ToListAsync(ct);

        foreach (var group in bindings.Where(b => b.LastSucceeded != null).GroupBy(b => b.CertificateId))
        {
            var certificate = certificates.FirstOrDefault(c => c.Id == group.Key);
            if (certificate?.Latest is null) continue;

            var behind = group.Where(b => b.LastSucceeded != certificate.Latest.Id).ToList();
            if (behind.Count == 0) continue;

            items.Add(new WorkItem(
                "not-installed",
                ExpiryCalculator.DaysUntilExpiry(certificate.Latest.NotAfter, now) <= 30 ? "critical" : "warning",
                certificate.CommonName,
                $"{behind.Count} place(s) still serve an older version: {string.Join(", ", behind.Select(b => b.Target).Distinct().Take(5))}"
                + (behind.Count > 5 ? " …" : ""),
                "Install the current one there",
                $"/certificates/{certificate.Id}",
                CertificateId: certificate.Id));
        }

        // ---- 4. Deployments that failed, and approvals that block one ------------------------
        var jobs = await db.DeploymentJobs.AsNoTracking()
            .Where(j => j.Status == DeploymentJobStatus.Failed
                        || j.Status == DeploymentJobStatus.PartiallyFailed
                        || j.Status == DeploymentJobStatus.RolledBack
                        || j.Status == DeploymentJobStatus.PendingApproval)
            .OrderByDescending(j => j.CreatedAt)
            .Take(20)
            .Select(j => new
            {
                j.Id,
                j.Status,
                j.CreatedAt,
                Certificate = j.CertificateVersion.Certificate.CommonName,
                Targets = j.Targets.Count,
            })
            .ToListAsync(ct);

        foreach (var j in jobs.Where(j => j.Status == DeploymentJobStatus.PendingApproval))
        {
            items.Add(new WorkItem("approval", "warning", j.Certificate,
                $"An installation on {j.Targets} place(s) is waiting for an approver.",
                "Review it", $"/activity/{j.Id}", JobId: j.Id));
        }

        // One row per certificate, not per attempt. Five failed retries of the same install are
        // one problem; listing them five times buries everything else on the screen.
        foreach (var group in jobs.Where(j => j.Status != DeploymentJobStatus.PendingApproval)
                     .GroupBy(j => j.Certificate))
        {
            var latest = group.First();
            var earlier = group.Count() - 1;
            items.Add(new WorkItem("deployment-failed", "critical", latest.Certificate,
                $"An installation {latest.Status.ToString().ToLowerInvariant()} on "
                + $"{latest.CreatedAt.LocalDateTime:d MMM HH:mm}"
                + (earlier > 0 ? $", and {earlier} earlier attempt(s) also failed." : "."),
                "See what failed", $"/activity/{latest.Id}", JobId: latest.Id));
        }

        // ---- 5. A runner that is down means nothing can be installed or discovered -----------
        var runners = await db.Runners.AsNoTracking()
            .Where(r => r.Status != RunnerStatus.Online)
            .Select(r => new { r.Id, r.Name, r.Status, r.LastHeartbeatAt })
            .ToListAsync(ct);

        foreach (var r in runners)
        {
            items.Add(new WorkItem(
                "runner-offline", "critical", r.Name,
                r.LastHeartbeatAt is null
                    ? "This runner has never checked in; nothing can be installed through it."
                    : $"Last heard from {(int)(now - r.LastHeartbeatAt.Value).TotalMinutes} minute(s) ago.",
                "Open runners", "/settings/runners"));
        }

        // Most urgent first, and within that the nearest deadline: the top of this list should be
        // the next thing worth doing, not the most recently changed row.
        return items
            .OrderBy(i => i.Severity == "critical" ? 0 : i.Severity == "warning" ? 1 : 2)
            .ThenBy(i => i.DaysLeft ?? int.MaxValue)
            .ThenBy(i => i.Title)
            .ToList();
    }
}
