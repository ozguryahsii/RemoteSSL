using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/certificates")]
public class CertificatesController(IRemoteSslDbContext db) : ControllerBase
{
    public record CertificateListItem(
        Guid Id, string CommonName, string DisplayName, string Health,
        string? IssuerDn, DateTimeOffset? NotAfter, int? DaysUntilExpiry,
        int MonitorCount, int VersionCount);

    public record CertificateDetail(
        Guid Id, string CommonName, string DisplayName, string Health,
        IReadOnlyList<VersionDto> Versions, IReadOnlyList<MonitorLinkDto> Monitors);

    public record VersionDto(
        Guid Id, string SerialNumber, string Sha256Thumbprint, string SubjectDn, string IssuerDn,
        DateTimeOffset NotBefore, DateTimeOffset NotAfter, int DaysUntilExpiry,
        string PublicKeyAlgorithm, int KeySize, string SignatureAlgorithm, string Status,
        IReadOnlyList<string> Sans);

    public record MonitorLinkDto(Guid MonitorId, string Host, int Port, string? Sni, DateTimeOffset LastSeenAt);

    [HttpGet]
    public async Task<IEnumerable<CertificateListItem>> List([FromQuery] string? status, CancellationToken ct)
    {
        var query = db.Certificates.AsNoTracking();
        if (Enum.TryParse<CertificateHealthStatus>(status, ignoreCase: true, out var health))
            query = query.Where(c => c.HealthStatus == health);

        var now = DateTimeOffset.UtcNow;
        var items = await query
            .Select(c => new
            {
                c.Id, c.CommonName, c.DisplayName, c.HealthStatus,
                MonitorCount = c.MonitorLinks.Count,
                VersionCount = c.Versions.Count,
                Latest = c.Versions.OrderByDescending(v => v.NotAfter)
                    .Select(v => new { v.IssuerDn, v.NotAfter })
                    .FirstOrDefault()
            })
            .OrderBy(x => x.CommonName)
            .ToListAsync(ct);

        return items.Select(x => new CertificateListItem(
            x.Id, x.CommonName, x.DisplayName, x.HealthStatus.ToString(),
            x.Latest?.IssuerDn, x.Latest?.NotAfter,
            x.Latest is null ? null : ExpiryCalculator.DaysUntilExpiry(x.Latest.NotAfter, now),
            x.MonitorCount, x.VersionCount));
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<CertificateDetail>> Get(Guid id, CancellationToken ct)
    {
        var cert = await db.Certificates
            .Include(c => c.Versions).ThenInclude(v => v.Sans)
            .Include(c => c.MonitorLinks).ThenInclude(l => l.MonitorEndpoint)
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cert is null) return NotFound();

        var now = DateTimeOffset.UtcNow;
        return new CertificateDetail(
            cert.Id, cert.CommonName, cert.DisplayName, cert.HealthStatus.ToString(),
            cert.Versions
                .OrderByDescending(v => v.NotAfter)
                .Select(v => new VersionDto(
                    v.Id, v.SerialNumber, v.Sha256Thumbprint, v.SubjectDn, v.IssuerDn,
                    v.NotBefore, v.NotAfter, ExpiryCalculator.DaysUntilExpiry(v.NotAfter, now),
                    v.PublicKeyAlgorithm, v.KeySize, v.SignatureAlgorithm, v.Status.ToString(),
                    v.Sans.Select(s => s.Value).ToList()))
                .ToList(),
            cert.MonitorLinks
                .Select(l => new MonitorLinkDto(
                    l.MonitorEndpointId, l.MonitorEndpoint.Host, l.MonitorEndpoint.Port,
                    l.MonitorEndpoint.Sni, l.LastSeenAt))
                .ToList());
    }
}
