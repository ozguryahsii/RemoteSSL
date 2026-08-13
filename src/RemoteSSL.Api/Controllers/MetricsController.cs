using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Prometheus text exposition of the design doc §32.1 metric set, using the metric
/// names the document specifies so existing dashboards/alerts can scrape RemoteSSL
/// directly. Values are computed on demand from the operational tables; no secret,
/// hostname-sensitive or per-certificate label is exported.
/// </summary>
[ApiController]
[Route("metrics")]
[AllowAnonymous]
public class MetricsController(IRemoteSslDbContext db, MetricsQuery metrics, AuditPipelineHealth auditHealth)
    : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var sb = new StringBuilder();

        void Write(string name, string help, string type, double? value, string? labels = null)
        {
            if (value is null) return;
            sb.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n');
            sb.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
            sb.Append(name);
            if (labels is not null) sb.Append('{').Append(labels).Append('}');
            sb.Append(' ').Append(value.Value.ToString("0.###", CultureInfo.InvariantCulture)).Append('\n');
        }

        // certificates_total / certificates_expiring
        var versions = await db.Certificates.AsNoTracking()
            .Select(c => c.Versions
                .Where(v => v.Status != CertificateVersionStatus.Superseded && v.Status != CertificateVersionStatus.Revoked)
                .OrderByDescending(v => v.NotAfter)
                .Select(v => (DateTimeOffset?)v.NotAfter)
                .FirstOrDefault())
            .ToListAsync(ct);
        var daysLeft = versions.Where(v => v is not null)
            .Select(v => ExpiryCalculator.DaysUntilExpiry(v!.Value, now)).ToList();

        Write("certificates_total", "Logical certificates in the inventory.", "gauge", versions.Count);
        Write("certificates_expiring", "Certificates expiring within 30 days.", "gauge",
            daysLeft.Count(d => d is <= 30 and >= 0));
        Write("certificates_expired", "Certificates already expired.", "gauge", daysLeft.Count(d => d < 0));

        // probe_success_rate / probe_latency
        var probeStatuses = await db.MonitorEndpoints.AsNoTracking()
            .Select(m => m.LastProbeStatus).ToListAsync(ct);
        var probed = probeStatuses.Where(s => s != ProbeStatus.NeverProbed).ToList();
        Write("probe_success_rate", "Share of monitors whose last probe succeeded (0-1).", "gauge",
            probed.Count == 0 ? null : (double)probed.Count(s => s == ProbeStatus.Success) / probed.Count);

        var probeLatency = await metrics.SummaryAsync(MetricsRecorder.ProbeLatency, TimeSpan.FromHours(24), ct);
        Write("probe_latency_seconds", "TLS probe duration over the last 24h.", "gauge",
            probeLatency.P50Ms / 1000.0, "quantile=\"0.5\"");
        Write("probe_latency_seconds", "TLS probe duration over the last 24h.", "gauge",
            probeLatency.P95Ms / 1000.0, "quantile=\"0.95\"");

        // deployment_success_rate / deployment_duration_seconds / rollback_count
        var jobs = await db.DeploymentJobs.AsNoTracking()
            .Select(j => new { j.Status, j.StartedAt, j.CompletedAt }).ToListAsync(ct);
        var finished = jobs.Where(j => j.CompletedAt is not null).ToList();
        Write("deployment_success_rate", "Share of finished deployment jobs that succeeded (0-1).", "gauge",
            finished.Count == 0 ? null : (double)finished.Count(j => j.Status == DeploymentJobStatus.Succeeded) / finished.Count);
        Write("deployment_duration_seconds", "Mean duration of finished deployment jobs.", "gauge",
            finished.Count == 0 ? null : finished.Where(j => j.StartedAt is not null)
                .Select(j => (j.CompletedAt!.Value - j.StartedAt!.Value).TotalSeconds)
                .DefaultIfEmpty(0).Average());
        Write("rollback_count", "Deployment jobs that rolled back or failed to roll back.", "counter",
            jobs.Count(j => j.Status is DeploymentJobStatus.RolledBack or DeploymentJobStatus.RollbackFailed));

        // runner_online / runner_offline / queue_depth
        var runnerStatuses = await db.Runners.AsNoTracking().Select(r => r.Status).ToListAsync(ct);
        Write("runner_online", "Runners currently online.", "gauge", runnerStatuses.Count(s => s == RunnerStatus.Online));
        Write("runner_offline", "Runners currently offline.", "gauge", runnerStatuses.Count(s => s != RunnerStatus.Online));
        Write("queue_depth", "Runner jobs queued or claimed but not finished.", "gauge",
            await db.RunnerJobs.CountAsync(j => j.Status == "Queued" || j.Status == "Claimed", ct));

        // ca_request_latency
        var caLatency = await metrics.SummaryAsync(MetricsRecorder.CaRequestLatency, TimeSpan.FromDays(7), ct);
        Write("ca_request_latency_seconds", "CA connector call duration over the last 7 days.", "gauge",
            caLatency.P50Ms / 1000.0, "quantile=\"0.5\"");
        Write("ca_request_latency_seconds", "CA connector call duration over the last 7 days.", "gauge",
            caLatency.P95Ms / 1000.0, "quantile=\"0.95\"");

        // renewal_failure_count / drift_detected_count
        Write("renewal_failure_count", "Certificate requests in a failed state.", "gauge",
            await db.CertificateRequests.CountAsync(r => r.State == CertificateRequestState.FailedRetryable
                                                         || r.State == CertificateRequestState.FailedBlocked, ct));
        var last7d = now.AddDays(-7);
        Write("drift_detected_count", "Drift / vantage-mismatch events in the last 7 days.", "gauge",
            await db.AuditEvents.CountAsync(e => (e.Action == "drift.detected" || e.Action == "vantage.mismatch")
                                                 && e.Timestamp > last7d, ct));
        Write("audit_pipeline_failure_count", "Audit writes that failed in the last 24h.", "gauge",
            auditHealth.Recent(TimeSpan.FromHours(24)).Count);

        return Content(sb.ToString(), "text/plain; version=0.0.4", Encoding.UTF8);
    }
}
