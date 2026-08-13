using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/monitors")]
public class MonitorsController(IRemoteSslDbContext db, MonitorProbeService probeService) : ControllerBase
{
    public record CreateMonitorRequest(string Host, int Port = 443, string? Sni = null, int? ProbeIntervalMinutes = null, Guid? RunnerId = null);
    public record UpdateMonitorRequest(bool? Enabled, int? ProbeIntervalMinutes, string? Host, int? Port, string? Sni, bool ClearSni = false, Guid? RunnerId = null, bool ClearRunner = false);

    public record MonitorDto(
        Guid Id, string Host, int Port, string? Sni, bool Enabled, int? ProbeIntervalMinutes, Guid? RunnerId,
        string LastProbeStatus, string? LastProbeError, DateTimeOffset? LastProbeAt,
        string? LastTlsProtocol, bool? LastHostnameValid, bool? LastChainValid, string? LastChainError,
        ObservedCertDto? ObservedCertificate);

    public record ObservedCertDto(
        Guid CertificateId, Guid VersionId, string CommonName, string IssuerDn,
        string Sha256Thumbprint, DateTimeOffset NotAfter, int DaysUntilExpiry, string Health);

    [HttpGet]
    public async Task<IEnumerable<MonitorDto>> List(CancellationToken ct)
    {
        var monitors = await db.MonitorEndpoints
            .Include(m => m.LastObservedVersion).ThenInclude(v => v!.Certificate)
            .OrderBy(m => m.Host).ThenBy(m => m.Port)
            .AsNoTracking()
            .ToListAsync(ct);
        return monitors.Select(ToDto);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<MonitorDto>> Get(Guid id, CancellationToken ct)
    {
        var monitor = await db.MonitorEndpoints
            .Include(m => m.LastObservedVersion).ThenInclude(v => v!.Certificate)
            .AsNoTracking()
            .FirstOrDefaultAsync(m => m.Id == id, ct);
        return monitor is null ? NotFound() : ToDto(monitor);
    }

    [HttpPost]
    public async Task<ActionResult<MonitorDto>> Create(CreateMonitorRequest request, CancellationToken ct)
    {
        var host = request.Host.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(host)) return ValidationProblem("Host is required.");
        if (request.Port is < 1 or > 65535) return ValidationProblem("Port must be between 1 and 65535.");

        var sni = string.IsNullOrWhiteSpace(request.Sni) ? null : request.Sni.Trim().ToLowerInvariant();
        var exists = await db.MonitorEndpoints.AnyAsync(
            m => m.Host == host && m.Port == request.Port && m.Sni == sni, ct);
        if (exists) return Conflict(new ProblemDetails { Title = "Monitor already exists for this host/port/SNI." });

        var monitor = new MonitorEndpoint
        {
            Id = Guid.NewGuid(),
            Host = host,
            Port = request.Port,
            Sni = sni,
            ProbeIntervalMinutes = request.ProbeIntervalMinutes,
            RunnerId = request.RunnerId,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.MonitorEndpoints.Add(monitor);
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(Get), new { id = monitor.Id }, ToDto(monitor));
    }

    [HttpPatch("{id:guid}")]
    public async Task<ActionResult<MonitorDto>> Update(Guid id, UpdateMonitorRequest request, CancellationToken ct)
    {
        var monitor = await db.MonitorEndpoints.FirstOrDefaultAsync(m => m.Id == id, ct);
        if (monitor is null) return NotFound();

        if (request.Enabled.HasValue) monitor.Enabled = request.Enabled.Value;
        if (request.ProbeIntervalMinutes.HasValue) monitor.ProbeIntervalMinutes = request.ProbeIntervalMinutes;
        if (!string.IsNullOrWhiteSpace(request.Host)) monitor.Host = request.Host.Trim().ToLowerInvariant();
        if (request.Port is >= 1 and <= 65535) monitor.Port = request.Port.Value;
        if (request.ClearSni) monitor.Sni = null;
        else if (!string.IsNullOrWhiteSpace(request.Sni)) monitor.Sni = request.Sni.Trim().ToLowerInvariant();
        if (request.ClearRunner) monitor.RunnerId = null;
        else if (request.RunnerId is not null) monitor.RunnerId = request.RunnerId;
        monitor.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return ToDto(monitor);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var monitor = await db.MonitorEndpoints.FirstOrDefaultAsync(m => m.Id == id, ct);
        if (monitor is null) return NotFound();
        db.MonitorEndpoints.Remove(monitor);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>
    /// On-demand probe (design doc §27.1). Runner-pinned monitors are probed from
    /// inside the segment: a probe job is queued and the result lands asynchronously.
    /// </summary>
    [HttpPost("{id:guid}/probe")]
    public async Task<ActionResult<MonitorDto>> Probe(Guid id, CancellationToken ct)
    {
        var pinned = await db.MonitorEndpoints.AsNoTracking().FirstOrDefaultAsync(m => m.Id == id, ct);
        if (pinned is null) return NotFound();
        if (pinned.RunnerId is not null)
        {
            await MonitorProbeService.QueueRunnerProbeAsync(db, pinned, ct);
            await db.SaveChangesAsync(ct);
            return Accepted(ToDto(pinned));
        }
        var monitor = await probeService.ProbeAsync(id, ct);
        return ToDto(monitor);
    }

    private static MonitorDto ToDto(MonitorEndpoint m)
    {
        ObservedCertDto? observed = null;
        if (m.LastObservedVersion is { } v)
        {
            var now = DateTimeOffset.UtcNow;
            observed = new ObservedCertDto(
                v.CertificateId, v.Id,
                v.Certificate?.CommonName ?? v.SubjectDn,
                v.IssuerDn, v.Sha256Thumbprint, v.NotAfter,
                ExpiryCalculator.DaysUntilExpiry(v.NotAfter, now),
                ExpiryCalculator.HealthFor(v.NotAfter, now).ToString());
        }

        return new MonitorDto(
            m.Id, m.Host, m.Port, m.Sni, m.Enabled, m.ProbeIntervalMinutes, m.RunnerId,
            m.LastProbeStatus.ToString(), m.LastProbeError, m.LastProbeAt,
            m.LastTlsProtocol, m.LastHostnameValid, m.LastChainValid, m.LastChainError,
            observed);
    }
}
