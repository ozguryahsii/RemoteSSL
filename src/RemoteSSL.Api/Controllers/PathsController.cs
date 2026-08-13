using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Service paths: the ordered TLS hops in front of an application (e.g. F5 VIP →
/// nginx → IIS backend). Analysis probes every hop and pinpoints the layer whose
/// certificate was left behind during a renewal.
/// </summary>
[ApiController]
[Route("api/v1/paths")]
public class PathsController(IRemoteSslDbContext db, MonitorProbeService probeService, AuditWriter audit) : ControllerBase
{
    public record CreatePathRequest(string Name, List<Guid> MonitorIds);
    public record UpdatePathRequest(string? Name, List<Guid>? MonitorIds);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.ServicePaths.AsNoTracking()
            .Select(p => new { p.Id, p.Name, p.MonitorIdsJson, p.CreatedAt })
            .ToListAsync(ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreatePathRequest req, CancellationToken ct)
    {
        if (req.MonitorIds.Count < 2)
            return ValidationProblem("A service path needs at least two hops (outermost first).");
        var known = await db.MonitorEndpoints.CountAsync(m => req.MonitorIds.Contains(m.Id), ct);
        if (known != req.MonitorIds.Distinct().Count())
            return ValidationProblem("One or more monitor ids do not exist.");

        var path = new ServicePath
        {
            Id = Guid.NewGuid(),
            Name = req.Name,
            MonitorIdsJson = JsonSerializer.Serialize(req.MonitorIds),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.ServicePaths.Add(path);
        audit.Append("user:api", "path.create", "service_path", path.Id.ToString(), "OK",
            new { req.Name, hops = req.MonitorIds.Count });
        await db.SaveChangesAsync(ct);
        return new { path.Id };
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdatePathRequest req, CancellationToken ct)
    {
        var path = await db.ServicePaths.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (path is null) return NotFound();
        if (!string.IsNullOrWhiteSpace(req.Name)) path.Name = req.Name;
        if (req.MonitorIds is { Count: >= 2 }) path.MonitorIdsJson = JsonSerializer.Serialize(req.MonitorIds);
        path.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var path = await db.ServicePaths.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (path is null) return NotFound();
        db.ServicePaths.Remove(path);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>
    /// Triggers a fresh probe on every hop (runner-pinned hops via their runner) and
    /// returns the current analysis. Runner-probed hops may report the previous
    /// observation until their probe job completes — re-fetch shortly after.
    /// </summary>
    [HttpPost("{id:guid}/analyze")]
    public async Task<ActionResult<object>> Analyze(Guid id, CancellationToken ct)
    {
        var path = await db.ServicePaths.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        if (path is null) return NotFound();
        var monitorIds = JsonSerializer.Deserialize<List<Guid>>(path.MonitorIdsJson) ?? [];

        foreach (var monitorId in monitorIds)
        {
            var monitor = await db.MonitorEndpoints.Include(m => m.LastObservedVersion)
                .FirstOrDefaultAsync(m => m.Id == monitorId, ct);
            if (monitor is null) continue;
            if (monitor.RunnerId is not null)
                await MonitorProbeService.QueueRunnerProbeAsync(db, monitor, ct);
            if (monitor.ExternalProbeEnabled)
                try { await probeService.ApplyResultAsync(monitor, await ProbeDirect(monitor, ct), ProbeVantage.External, ct); }
                catch { /* probe failures are recorded on the monitor itself */ }
        }
        await db.SaveChangesAsync(ct);
        return await BuildAnalysis(path, monitorIds, ct);
    }

    [HttpGet("{id:guid}/analysis")]
    public async Task<ActionResult<object>> Analysis(Guid id, CancellationToken ct)
    {
        var path = await db.ServicePaths.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);
        if (path is null) return NotFound();
        var monitorIds = JsonSerializer.Deserialize<List<Guid>>(path.MonitorIdsJson) ?? [];
        return await BuildAnalysis(path, monitorIds, ct);
    }

    private async Task<TlsProbeResult> ProbeDirect(MonitorEndpoint monitor, CancellationToken ct)
    {
        var prober = HttpContext.RequestServices.GetRequiredService<ITlsProber>();
        return await prober.ProbeAsync(monitor.Host, monitor.Port, monitor.Sni, ct);
    }

    /// <summary>
    /// Verdict logic: hops serving different thumbprints than the freshest hop are
    /// flagged as stale (the layer someone forgot during renewal); unreachable and
    /// expired/critical hops are flagged too.
    /// </summary>
    private async Task<object> BuildAnalysis(ServicePath path, List<Guid> monitorIds, CancellationToken ct)
    {
        var monitors = await db.MonitorEndpoints.AsNoTracking()
            .Include(m => m.LastObservedVersion)
            .Where(m => monitorIds.Contains(m.Id))
            .ToListAsync(ct);
        var ordered = monitorIds
            .Select(mid => monitors.FirstOrDefault(m => m.Id == mid))
            .Where(m => m is not null).Cast<MonitorEndpoint>().ToList();

        var now = DateTimeOffset.UtcNow;
        var freshest = ordered
            .Where(m => m.LastObservedVersion is not null)
            .OrderByDescending(m => m.LastObservedVersion!.NotAfter)
            .FirstOrDefault()?.LastObservedVersion;

        var hops = ordered.Select((m, i) =>
        {
            var v = m.LastObservedVersion;
            string status; string detail;
            if (m.LastProbeStatus != ProbeStatus.Success || v is null)
            {
                status = "Unreachable";
                detail = $"{m.LastProbeStatus}: {m.LastProbeError}" +
                         (m.RunnerId is null ? " — internal endpoint? Assign a runner to probe from inside the segment." : "");
            }
            else if (v.NotAfter < now)
            {
                status = "Expired";
                detail = $"expired {(int)(now - v.NotAfter).TotalDays} day(s) ago";
            }
            else if (freshest is not null && v.Sha256Thumbprint != freshest.Sha256Thumbprint)
            {
                status = "StaleCertificate";
                detail = $"serves a different certificate than the freshest hop " +
                         $"(this: {v.NotAfter:yyyy-MM-dd}, freshest: {freshest.NotAfter:yyyy-MM-dd}) — " +
                         "this layer was likely skipped during the last renewal";
            }
            else
            {
                status = ExpiryCalculator.HealthFor(v.NotAfter, now).ToString();
                detail = $"{ExpiryCalculator.DaysUntilExpiry(v.NotAfter, now)} day(s) left";
            }
            return new
            {
                Order = i + 1,
                MonitorId = m.Id,
                Endpoint = $"{m.Host}:{m.Port}" + (m.Sni is not null ? $" (SNI {m.Sni})" : ""),
                ProbedVia = m.RunnerId is null ? "control-plane" : "runner",
                LastProbeAt = m.LastProbeAt,
                CommonName = v?.SubjectDn,
                Thumbprint = v?.Sha256Thumbprint,
                NotAfter = v?.NotAfter,
                Status = status,
                Detail = detail
            };
        }).ToList();

        var problems = hops.Where(h => h.Status is "Unreachable" or "Expired" or "StaleCertificate" or "Critical").ToList();
        var verdict = problems.Count == 0
            ? "OK — every hop serves a consistent, valid certificate."
            : "ATTENTION — " + string.Join("; ", problems.Select(p => $"hop {p.Order} ({p.Endpoint}): {p.Status}"));

        return new { path.Id, path.Name, Verdict = verdict, Hops = hops };
    }
}
