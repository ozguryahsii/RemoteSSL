using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/monitors")]
public class MonitorsController(IRemoteSslDbContext db, MonitorProbeService probeService) : ControllerBase
{
    public record CreateMonitorRequest(string Host, int Port = 443, string? Sni = null, int? ProbeIntervalMinutes = null,
        Guid? RunnerId = null, bool ExternalProbeEnabled = true,
        int? TimeoutSeconds = null, int RetryCount = 0,
        string? HealthCheckUrl = null, int? HealthCheckExpectedStatus = null);
    public record UpdateMonitorRequest(bool? Enabled, int? ProbeIntervalMinutes, string? Host, int? Port, string? Sni,
        bool ClearSni = false, Guid? RunnerId = null, bool ClearRunner = false, bool? ExternalProbeEnabled = null,
        int? TimeoutSeconds = null, bool ClearTimeout = false, int? RetryCount = null,
        string? HealthCheckUrl = null, bool ClearHealthCheck = false, int? HealthCheckExpectedStatus = null);

    public record MonitorDto(
        Guid Id, string Host, int Port, string? Sni, bool Enabled, int? ProbeIntervalMinutes, Guid? RunnerId,
        bool ExternalProbeEnabled,
        VantageDto External, VantageDto Internal,
        string Verdict, string VerdictDetail,
        // §5.2 probe policy and §2.1 application reachability
        int? TimeoutSeconds, int RetryCount, string Protocol,
        string? HealthCheckUrl, int? HealthCheckExpectedStatus, string HealthCheckStatus,
        string? HealthCheckDetail, DateTimeOffset? HealthCheckAt, int? HealthCheckLatencyMs,
        // §26.3 endpoint screen: expected certificate, drift, managed target and binding
        ExpectedDto? Expected, string DriftStatus, IReadOnlyList<BindingLinkDto> Bindings,
        // Legacy flat fields (external vantage) kept for existing consumers.
        string LastProbeStatus, string? LastProbeError, DateTimeOffset? LastProbeAt,
        string? LastTlsProtocol, bool? LastHostnameValid, bool? LastChainValid, string? LastChainError,
        ObservedCertDto? ObservedCertificate);

    /// <summary>The certificate RemoteSSL believes should be live here (§26.3).</summary>
    public record ExpectedDto(
        Guid CertificateId, Guid VersionId, string CommonName, string Sha256Thumbprint,
        DateTimeOffset NotAfter, string Status);

    /// <summary>Managed target + credential + binding behind this endpoint (§26.3).</summary>
    public record BindingLinkDto(
        Guid BindingId, Guid TargetId, string TargetName, string Adapter,
        string StoreType, string StorePath, string? Alias,
        string? CredentialName, string CredentialStatus, string ServiceBindingJson);

    /// <summary>One vantage's view of the endpoint (outside vs inside).</summary>
    public record VantageDto(
        string ProbeStatus, string? ProbeError, DateTimeOffset? ProbeAt, string? TlsProtocol,
        bool? HostnameValid, bool? ChainValid, string? ChainError, ObservedCertDto? Certificate,
        string? CipherSuite);

    public record ObservedCertDto(
        Guid CertificateId, Guid VersionId, string CommonName, string IssuerDn,
        string Sha256Thumbprint, DateTimeOffset NotAfter, int DaysUntilExpiry, string Health);

    [HttpGet]
    public async Task<IEnumerable<MonitorDto>> List(CancellationToken ct)
    {
        var monitors = await db.MonitorEndpoints
            .Include(m => m.LastObservedVersion).ThenInclude(v => v!.Certificate)
            .Include(m => m.InternalObservedVersion).ThenInclude(v => v!.Certificate)
            .Include(m => m.CertificateLinks)
            .OrderBy(m => m.Host).ThenBy(m => m.Port)
            .AsNoTracking()
            .ToListAsync(ct);

        var result = new List<MonitorDto>(monitors.Count);
        foreach (var m in monitors) result.Add(await EnrichAsync(m, ct));
        return result;
    }

    /// <summary>
    /// Adds the §26.3 fields: the expected (active) certificate for this endpoint,
    /// the resulting drift status, and the managed target/credential/binding behind it.
    /// </summary>
    private async Task<MonitorDto> EnrichAsync(MonitorEndpoint m, CancellationToken ct)
    {
        var dto = ToDto(m);
        var certIds = m.CertificateLinks.Select(l => l.CertificateId).ToList();
        if (certIds.Count == 0)
            return dto with { DriftStatus = "Unknown", Bindings = [] };

        var expectedVersion = await db.CertificateVersions.AsNoTracking()
            .Include(v => v.Certificate)
            .Where(v => certIds.Contains(v.CertificateId) && v.Status == CertificateVersionStatus.Active)
            .OrderByDescending(v => v.NotAfter)
            .FirstOrDefaultAsync(ct);

        var expected = expectedVersion is null ? null : new ExpectedDto(
            expectedVersion.CertificateId, expectedVersion.Id,
            expectedVersion.Certificate.CommonName, expectedVersion.Sha256Thumbprint,
            expectedVersion.NotAfter, expectedVersion.Status.ToString());

        var observed = m.LastObservedVersion?.Sha256Thumbprint ?? m.InternalObservedVersion?.Sha256Thumbprint;
        var drift = expected is null ? "NoExpectedVersion"
            : observed is null ? "NotObserved"
            : string.Equals(observed, expected.Sha256Thumbprint, StringComparison.OrdinalIgnoreCase) ? "InSync"
            : "Drift";

        var bindings = await db.DeploymentBindings.AsNoTracking()
            .Where(b => certIds.Contains(b.CertificateId))
            .Select(b => new BindingLinkDto(
                b.Id, b.CertificateStore.TargetId, b.CertificateStore.Target.Name,
                b.CertificateStore.Target.AdapterType, b.CertificateStore.StoreType,
                b.CertificateStore.StorePath, b.CertificateStore.Alias,
                b.CertificateStore.Target.CredentialRefId == null ? null
                    : db.CredentialRefs.Where(c => c.Id == b.CertificateStore.Target.CredentialRefId)
                        .Select(c => c.Name).FirstOrDefault(),
                b.CertificateStore.Target.CredentialRefId == null ? "none"
                    : db.CredentialRefs.Where(c => c.Id == b.CertificateStore.Target.CredentialRefId)
                        .Select(c => c.EncryptedSecret != null ? "stored (encrypted)" : "external provider")
                        .FirstOrDefault() ?? "unknown",
                b.ServiceBindingJson))
            .ToListAsync(ct);

        return dto with { Expected = expected, DriftStatus = drift, Bindings = bindings };
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<MonitorDto>> Get(Guid id, CancellationToken ct)
    {
        var monitor = await db.MonitorEndpoints
            .Include(m => m.LastObservedVersion).ThenInclude(v => v!.Certificate)
            .Include(m => m.InternalObservedVersion).ThenInclude(v => v!.Certificate)
            .Include(m => m.CertificateLinks)
            .AsNoTracking()
            .FirstOrDefaultAsync(m => m.Id == id, ct);
        return monitor is null ? NotFound() : await EnrichAsync(monitor, ct);
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
            TimeoutSeconds = request.TimeoutSeconds,
            RetryCount = Math.Clamp(request.RetryCount, 0, 5),
            HealthCheckUrl = string.IsNullOrWhiteSpace(request.HealthCheckUrl) ? null : request.HealthCheckUrl.Trim(),
            HealthCheckExpectedStatus = request.HealthCheckExpectedStatus,
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
        if (request.ClearTimeout) monitor.TimeoutSeconds = null;
        else if (request.TimeoutSeconds is { } t) monitor.TimeoutSeconds = Math.Clamp(t, 1, 120);
        if (request.RetryCount is { } r) monitor.RetryCount = Math.Clamp(r, 0, 5);
        if (request.ClearHealthCheck)
        {
            monitor.HealthCheckUrl = null;
            monitor.HealthCheckExpectedStatus = null;
            monitor.HealthCheckStatus = "NotConfigured";
            monitor.HealthCheckDetail = null;
            monitor.HealthCheckLatencyMs = null;
        }
        else if (!string.IsNullOrWhiteSpace(request.HealthCheckUrl))
        {
            monitor.HealthCheckUrl = request.HealthCheckUrl.Trim();
            monitor.HealthCheckExpectedStatus = request.HealthCheckExpectedStatus;
        }
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
            .Include(x => x.CertificateLinks)
            .AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        return m is null ? null : await EnrichAsync(m, ct);
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
            m.LastHostnameValid, m.LastChainValid, m.LastChainError, ToCertDto(m.LastObservedVersion),
            m.LastCipherSuite);
        var inside = new VantageDto(
            m.InternalProbeStatus.ToString(), m.InternalProbeError, m.InternalProbeAt, m.InternalTlsProtocol,
            m.InternalHostnameValid, m.InternalChainValid, m.InternalChainError, ToCertDto(m.InternalObservedVersion),
            m.InternalCipherSuite);

        var (verdict, detail) = VantageComparison.Compare(
            internalConfigured: m.RunnerId is not null,
            m.LastProbeStatus, m.LastObservedVersion?.Sha256Thumbprint, m.LastObservedVersion?.NotAfter,
            m.InternalProbeStatus, m.InternalObservedVersion?.Sha256Thumbprint, m.InternalObservedVersion?.NotAfter);

        return new MonitorDto(
            m.Id, m.Host, m.Port, m.Sni, m.Enabled, m.ProbeIntervalMinutes, m.RunnerId, m.ExternalProbeEnabled,
            external, inside, verdict.ToString(), detail,
            m.TimeoutSeconds, m.RetryCount, m.Protocol,
            m.HealthCheckUrl, m.HealthCheckExpectedStatus, m.HealthCheckStatus,
            m.HealthCheckDetail, m.HealthCheckAt, m.HealthCheckLatencyMs,
            null, "Unknown", [],
            m.LastProbeStatus.ToString(), m.LastProbeError, m.LastProbeAt,
            m.LastTlsProtocol, m.LastHostnameValid, m.LastChainValid, m.LastChainError,
            external.Certificate);
    }
}
