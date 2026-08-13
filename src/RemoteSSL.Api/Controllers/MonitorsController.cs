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
    public record CreateMonitorRequest(string Host, int Port = 443, string? Sni = null, int? ProbeIntervalMinutes = null,
        Guid? RunnerId = null, bool ExternalProbeEnabled = true);
    public record UpdateMonitorRequest(bool? Enabled, int? ProbeIntervalMinutes, string? Host, int? Port, string? Sni,
        bool ClearSni = false, Guid? RunnerId = null, bool ClearRunner = false, bool? ExternalProbeEnabled = null);

    public record MonitorDto(
        Guid Id, string Host, int Port, string? Sni, bool Enabled, int? ProbeIntervalMinutes, Guid? RunnerId,
        bool ExternalProbeEnabled,
        VantageDto External, VantageDto Internal,
        string Verdict, string VerdictDetail,
        // Legacy flat fields (external vantage) kept for existing consumers.
        string LastProbeStatus, string? LastProbeError, DateTimeOffset? LastProbeAt,
        string? LastTlsProtocol, bool? LastHostnameValid, bool? LastChainValid, string? LastChainError,
        ObservedCertDto? ObservedCertificate);

    /// <summary>One vantage's view of the endpoint (outside vs inside).</summary>
    public record VantageDto(
        string ProbeStatus, string? ProbeError, DateTimeOffset? ProbeAt, string? TlsProtocol,
        bool? HostnameValid, bool? ChainValid, string? ChainError, ObservedCertDto? Certificate);

    public record ObservedCertDto(
        Guid CertificateId, Guid VersionId, string CommonName, string IssuerDn,
        string Sha256Thumbprint, DateTimeOffset NotAfter, int DaysUntilExpiry, string Health);

    [HttpGet]
    public async Task<IEnumerable<MonitorDto>> List(CancellationToken ct)
    {
        var monitors = await db.MonitorEndpoints
            .Include(m => m.LastObservedVersion).ThenInclude(v => v!.Certificate)
            .Include(m => m.InternalObservedVersion).ThenInclude(v => v!.Certificate)
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
            .Include(m => m.InternalObservedVersion).ThenInclude(v => v!.Certificate)
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
            ExternalProbeEnabled = request.ExternalProbeEnabled,
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
        if (request.ExternalProbeEnabled.HasValue) monitor.ExternalProbeEnabled = request.ExternalProbeEnabled.Value;
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
        var target = await db.MonitorEndpoints.FirstOrDefaultAsync(m => m.Id == id, ct);
        if (target is null) return NotFound();

        // Internal vantage runs asynchronously on the runner; external runs inline.
        if (target.RunnerId is not null)
        {
            await MonitorProbeService.QueueRunnerProbeAsync(db, target, ct);
            await db.SaveChangesAsync(ct);
        }
        if (!target.ExternalProbeEnabled) return Accepted(await GetDtoAsync(id, ct));

        await probeService.ProbeAsync(id, ct);
        return await GetDtoAsync(id, ct) is { } dto ? dto : NotFound();
    }

    private async Task<MonitorDto?> GetDtoAsync(Guid id, CancellationToken ct)
    {
        var m = await db.MonitorEndpoints
            .Include(x => x.LastObservedVersion).ThenInclude(v => v!.Certificate)
            .Include(x => x.InternalObservedVersion).ThenInclude(v => v!.Certificate)
            .AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        return m is null ? null : ToDto(m);
    }

    private static ObservedCertDto? ToCertDto(CertificateVersion? v)
    {
        if (v is null) return null;
        var now = DateTimeOffset.UtcNow;
        return new ObservedCertDto(
            v.CertificateId, v.Id, v.Certificate?.CommonName ?? v.SubjectDn, v.IssuerDn,
            v.Sha256Thumbprint, v.NotAfter,
            ExpiryCalculator.DaysUntilExpiry(v.NotAfter, now),
            ExpiryCalculator.HealthFor(v.NotAfter, now).ToString());
    }

    private static MonitorDto ToDto(MonitorEndpoint m)
    {
        var external = new VantageDto(
            m.LastProbeStatus.ToString(), m.LastProbeError, m.LastProbeAt, m.LastTlsProtocol,
            m.LastHostnameValid, m.LastChainValid, m.LastChainError, ToCertDto(m.LastObservedVersion));
        var inside = new VantageDto(
            m.InternalProbeStatus.ToString(), m.InternalProbeError, m.InternalProbeAt, m.InternalTlsProtocol,
            m.InternalHostnameValid, m.InternalChainValid, m.InternalChainError, ToCertDto(m.InternalObservedVersion));

        var (verdict, detail) = VantageComparison.Compare(
            internalConfigured: m.RunnerId is not null,
            m.LastProbeStatus, m.LastObservedVersion?.Sha256Thumbprint, m.LastObservedVersion?.NotAfter,
            m.InternalProbeStatus, m.InternalObservedVersion?.Sha256Thumbprint, m.InternalObservedVersion?.NotAfter);

        return new MonitorDto(
            m.Id, m.Host, m.Port, m.Sni, m.Enabled, m.ProbeIntervalMinutes, m.RunnerId, m.ExternalProbeEnabled,
            external, inside, verdict.ToString(), detail,
            m.LastProbeStatus.ToString(), m.LastProbeError, m.LastProbeAt,
            m.LastTlsProtocol, m.LastHostnameValid, m.LastChainValid, m.LastChainError,
            external.Certificate);
    }
}
