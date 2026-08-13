using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/certificates")]
public class CertificatesController(IRemoteSslDbContext db) : ControllerBase
{
    /// <summary>Inventory row per design doc §26.1: Certificate | Expiry | CA | Managed | Deployments | Auto Renew | Status.</summary>
    public record CertificateListItem(
        Guid Id, string CommonName, string DisplayName, string Health,
        string? IssuerDn, string? Ca, DateTimeOffset? NotAfter, int? DaysUntilExpiry,
        bool Managed, int DeploymentCount, bool AutoRenew,
        string? Environment, string? OwnerId, int MonitorCount, int VersionCount);

    /// <summary>
    /// Everything the nine certificate detail tabs need (design doc §26.2):
    /// Overview, Lifecycle, Deployments, Certificate Stores, Monitoring, Renewal,
    /// Files/Artifacts, Approvals, History/Audit.
    /// </summary>
    public record CertificateDetail(
        Guid Id, string CommonName, string DisplayName, string Health,
        OverviewDto Overview,
        IReadOnlyList<VersionDto> Versions,
        IReadOnlyList<LifecycleEventDto> Lifecycle,
        IReadOnlyList<DeploymentDto> Deployments,
        IReadOnlyList<StoreDto> Stores,
        IReadOnlyList<MonitorLinkDto> Monitors,
        RenewalDto? Renewal,
        IReadOnlyList<ArtifactDto> Artifacts,
        IReadOnlyList<ApprovalDto> Approvals,
        IReadOnlyList<AuditDto> History);

    public record OverviewDto(
        string? Environment, string? OwnerId, string? Ca, string? IssuerDn,
        DateTimeOffset? NotAfter, int? DaysUntilExpiry, bool Managed, int DeploymentCount,
        bool AutoRenew, int MonitorCount, IReadOnlyList<string> Sans,
        DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

    public record LifecycleEventDto(DateTimeOffset At, string Stage, string Detail, string? Actor);

    public record DeploymentDto(
        Guid JobId, string Status, string Strategy, string? RequestedBy, string? ApprovedBy,
        int TargetCount, int FailedTargets, DateTimeOffset CreatedAt, DateTimeOffset? CompletedAt);

    public record StoreDto(
        Guid BindingId, Guid StoreId, string Target, string Adapter, string StoreType,
        string StorePath, string? Alias, string ServiceBindingJson);

    public record RenewalDto(
        Guid PolicyId, string Name, bool Enabled, int TriggerDays, bool RotateKey,
        bool AutoDeploy, bool ApprovalRequired, string? MaintenanceWindowJson,
        int? DaysUntilTrigger, string? CaConnector);

    public record ArtifactDto(
        Guid VersionId, string Kind, string Description, bool HasPrivateKey, DateTimeOffset CreatedAt);

    public record ApprovalDto(
        Guid Id, Guid DeploymentJobId, string Status, string? RequestedBy, string? DecidedBy,
        string? Reason, DateTimeOffset CreatedAt, DateTimeOffset? DecidedAt);

    public record AuditDto(
        long Id, DateTimeOffset Timestamp, string Actor, string Action, string Result, string DetailsJson);

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
                c.Id, c.CommonName, c.DisplayName, c.HealthStatus, c.Environment, c.OwnerId,
                AutoRenew = c.RenewalPolicyId != null,
                MonitorCount = c.MonitorLinks.Count,
                VersionCount = c.Versions.Count,
                DeploymentCount = db.DeploymentBindings.Count(b => b.CertificateId == c.Id),
                CaName = db.CertificateRequests
                    .Where(r => r.CertificateId == c.Id && r.CaConnectorId != null)
                    .OrderByDescending(r => r.CreatedAt)
                    .Select(r => db.CaConnectors.Where(k => k.Id == r.CaConnectorId).Select(k => k.Name).FirstOrDefault())
                    .FirstOrDefault(),
                Latest = c.Versions.OrderByDescending(v => v.NotAfter)
                    .Select(v => new { v.IssuerDn, v.NotAfter })
                    .FirstOrDefault()
            })
            .OrderBy(x => x.CommonName)
            .ToListAsync(ct);

        return items.Select(x => new CertificateListItem(
            x.Id, x.CommonName, x.DisplayName, x.HealthStatus.ToString(),
            x.Latest?.IssuerDn,
            // "CA" column: the connector that issued it, falling back to the issuer CN.
            x.CaName ?? IssuerShortName(x.Latest?.IssuerDn),
            x.Latest?.NotAfter,
            x.Latest is null ? null : ExpiryCalculator.DaysUntilExpiry(x.Latest.NotAfter, now),
            x.DeploymentCount > 0, x.DeploymentCount, x.AutoRenew,
            x.Environment, x.OwnerId, x.MonitorCount, x.VersionCount));
    }

    /// <summary>Pulls the CN out of an issuer DN for the compact "CA" column.</summary>
    private static string? IssuerShortName(string? issuerDn)
    {
        if (string.IsNullOrWhiteSpace(issuerDn)) return null;
        var cn = issuerDn.Split(',').Select(p => p.Trim())
            .FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
        return cn?[3..] ?? issuerDn;
    }

    public record UpdateCertificateRequest(string? DisplayName, string? Environment, string? OwnerId);

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateCertificateRequest req, CancellationToken ct)
    {
        var cert = await db.Certificates.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cert is null) return NotFound();
        if (!string.IsNullOrWhiteSpace(req.DisplayName)) cert.DisplayName = req.DisplayName;
        if (req.Environment is not null) cert.Environment = req.Environment;
        if (req.OwnerId is not null) cert.OwnerId = req.OwnerId;
        cert.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var cert = await db.Certificates.Include(c => c.Versions).Include(c => c.MonitorLinks)
            .FirstOrDefaultAsync(c => c.Id == id, ct);
        if (cert is null) return NotFound();
        if (await db.DeploymentBindings.AnyAsync(b => b.CertificateId == id, ct))
            return Conflict(new ProblemDetails { Title = "Certificate has deployment bindings; delete them first." });
        var versionIds = cert.Versions.Select(v => v.Id).ToList();
        var monitors = await db.MonitorEndpoints
            .Where(m => m.LastObservedVersionId != null && versionIds.Contains(m.LastObservedVersionId.Value))
            .ToListAsync(ct);
        foreach (var m in monitors) m.LastObservedVersionId = null;
        db.Certificates.Remove(cert);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>Deployment bindings of this certificate (for the deploy wizard).</summary>
    [HttpGet("{id:guid}/bindings")]
    public async Task<IEnumerable<object>> Bindings(Guid id, CancellationToken ct) =>
        await db.DeploymentBindings.AsNoTracking()
            .Where(b => b.CertificateId == id)
            .Select(b => new
            {
                b.Id,
                Target = b.CertificateStore.Target.Name,
                Adapter = b.CertificateStore.Target.AdapterType,
                Store = b.CertificateStore.StorePath
            }).ToListAsync(ct);

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
        var versions = cert.Versions.OrderByDescending(v => v.NotAfter).ToList();
        var latest = versions.FirstOrDefault();
        var versionIds = versions.Select(v => v.Id).ToList();

        // --- Requests feeding the lifecycle + the CA that issued it ------------------
        var requests = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.CertificateId == id || (r.IssuedVersionId != null && versionIds.Contains(r.IssuedVersionId.Value)))
            .OrderBy(r => r.CreatedAt)
            .ToListAsync(ct);
        var lastCaRequest = requests.LastOrDefault(r => r.CaConnectorId != null);
        var caName = lastCaRequest is null ? null
            : await db.CaConnectors.Where(k => k.Id == lastCaRequest.CaConnectorId)
                .Select(k => k.Name).FirstOrDefaultAsync(ct);

        // --- Deployments -------------------------------------------------------------
        var deployments = await db.DeploymentJobs.AsNoTracking()
            .Where(j => versionIds.Contains(j.CertificateVersionId))
            .OrderByDescending(j => j.CreatedAt)
            .Select(j => new DeploymentDto(
                j.Id, j.Status.ToString(), j.Strategy, j.RequestedBy, j.ApprovedBy,
                j.Targets.Count,
                j.Targets.Count(t => t.Status == DeploymentJobStatus.Failed || t.Status == DeploymentJobStatus.RolledBack),
                j.CreatedAt, j.CompletedAt))
            .ToListAsync(ct);

        // --- Certificate stores this certificate is bound to --------------------------
        var stores = await db.DeploymentBindings.AsNoTracking()
            .Where(b => b.CertificateId == id)
            .Select(b => new StoreDto(
                b.Id, b.CertificateStoreId,
                b.CertificateStore.Target.Name, b.CertificateStore.Target.AdapterType,
                b.CertificateStore.StoreType, b.CertificateStore.StorePath,
                b.CertificateStore.Alias, b.ServiceBindingJson))
            .ToListAsync(ct);

        // --- Renewal policy -----------------------------------------------------------
        RenewalDto? renewal = null;
        if (cert.RenewalPolicyId is { } policyId)
        {
            var p = await db.RenewalPolicies.AsNoTracking().FirstOrDefaultAsync(x => x.Id == policyId, ct);
            if (p is not null)
            {
                var caConnector = p.CaConnectorId is null ? null
                    : await db.CaConnectors.Where(k => k.Id == p.CaConnectorId).Select(k => k.Name).FirstOrDefaultAsync(ct);
                renewal = new RenewalDto(p.Id, p.Name, p.Enabled, p.TriggerDays, p.RotateKey,
                    p.AutoDeploy, p.ApprovalRequired, p.MaintenanceWindowJson,
                    latest is null ? null : ExpiryCalculator.DaysUntilExpiry(latest.NotAfter, now) - p.TriggerDays,
                    caConnector);
            }
        }

        // --- Approvals raised on this certificate's deployment jobs -------------------
        var jobIds = deployments.Select(d => d.JobId).ToList();
        var approvals = await db.ApprovalRequests.AsNoTracking()
            .Where(a => jobIds.Contains(a.DeploymentJobId))
            .OrderByDescending(a => a.CreatedAt)
            .Select(a => new ApprovalDto(a.Id, a.DeploymentJobId, a.Status, a.RequestedBy,
                a.DecidedBy, a.Reason, a.CreatedAt, a.DecidedAt))
            .ToListAsync(ct);

        // --- Audit trail across the certificate, versions, requests and jobs ----------
        var objectIds = new List<string> { id.ToString() };
        objectIds.AddRange(versionIds.Select(v => v.ToString()));
        objectIds.AddRange(requests.Select(r => r.Id.ToString()));
        objectIds.AddRange(jobIds.Select(j => j.ToString()));
        var history = await db.AuditEvents.AsNoTracking()
            .Where(e => e.ObjectId != null && objectIds.Contains(e.ObjectId))
            .OrderByDescending(e => e.Timestamp).Take(100)
            .Select(e => new AuditDto(e.Id, e.Timestamp, e.Actor, e.Action, e.Result, e.DetailsJson))
            .ToListAsync(ct);

        // --- Lifecycle: requests, version issuance and deployment milestones ----------
        var lifecycle = new List<LifecycleEventDto>();
        foreach (var r in requests)
        {
            lifecycle.Add(new LifecycleEventDto(r.CreatedAt, "Requested",
                $"{r.KeyAlgorithm} {r.KeySizeOrCurve}, key origin {r.KeyOrigin}", r.RequestedBy));
            if (r.State != CertificateRequestState.Draft)
                lifecycle.Add(new LifecycleEventDto(r.UpdatedAt, r.State.ToString(),
                    r.ErrorMessage ?? "state transition", r.RequestedBy));
        }
        foreach (var v in versions)
            lifecycle.Add(new LifecycleEventDto(v.CreatedAt, $"Version {v.Status}",
                $"serial {v.SerialNumber}, valid to {v.NotAfter:yyyy-MM-dd}", null));
        foreach (var d in deployments)
            lifecycle.Add(new LifecycleEventDto(d.CompletedAt ?? d.CreatedAt, $"Deployment {d.Status}",
                $"{d.TargetCount} target(s), strategy {d.Strategy}", d.RequestedBy));
        lifecycle = lifecycle.OrderByDescending(e => e.At).ToList();

        // --- Artifacts: what material exists per version (§26.2 Files / Artifacts) -----
        var artifacts = versions.SelectMany(v => new List<ArtifactDto>
        {
            new(v.Id, "certificate", $"Leaf certificate PEM (serial {v.SerialNumber})", false, v.CreatedAt),
            new(v.Id, "chain", v.PemChain is null ? "No chain captured" : "Intermediate chain PEM", false, v.CreatedAt),
            new(v.Id, "private-key", v.EncryptedPrivateKeyPem is null
                ? "No private key held by RemoteSSL (on-target or monitor-observed)"
                : "Private key held encrypted — never downloadable, used for PFX/Windows deployment",
                v.EncryptedPrivateKeyPem is not null, v.CreatedAt)
        }).ToList();
        artifacts.AddRange(requests.Where(r => r.CsrPem is not null)
            .Select(r => new ArtifactDto(r.IssuedVersionId ?? Guid.Empty, "csr",
                $"CSR for {r.CommonName}", false, r.CreatedAt)));

        var overview = new OverviewDto(
            cert.Environment, cert.OwnerId,
            caName ?? IssuerShortName(latest?.IssuerDn), latest?.IssuerDn,
            latest?.NotAfter,
            latest is null ? null : ExpiryCalculator.DaysUntilExpiry(latest.NotAfter, now),
            stores.Count > 0, stores.Count, cert.RenewalPolicyId != null, cert.MonitorLinks.Count,
            latest?.Sans.Select(x => x.Value).ToList() ?? [],
            cert.CreatedAt, cert.UpdatedAt);

        return new CertificateDetail(
            cert.Id, cert.CommonName, cert.DisplayName, cert.HealthStatus.ToString(),
            overview,
            versions.Select(v => new VersionDto(
                    v.Id, v.SerialNumber, v.Sha256Thumbprint, v.SubjectDn, v.IssuerDn,
                    v.NotBefore, v.NotAfter, ExpiryCalculator.DaysUntilExpiry(v.NotAfter, now),
                    v.PublicKeyAlgorithm, v.KeySize, v.SignatureAlgorithm, v.Status.ToString(),
                    v.Sans.Select(x => x.Value).ToList()))
                .ToList(),
            lifecycle, deployments, stores,
            cert.MonitorLinks
                .Select(l => new MonitorLinkDto(
                    l.MonitorEndpointId, l.MonitorEndpoint.Host, l.MonitorEndpoint.Port,
                    l.MonitorEndpoint.Sni, l.LastSeenAt))
                .ToList(),
            renewal, artifacts, approvals, history);
    }

    /// <summary>
    /// Downloads a version's public material (§26.2 Files / Artifacts). Private key
    /// material is never served over the API (§7.3 / §22.3).
    /// </summary>
    [HttpGet("versions/{versionId:guid}/download")]
    public async Task<IActionResult> DownloadArtifact(Guid versionId, [FromQuery] string kind, CancellationToken ct)
    {
        var v = await db.CertificateVersions.AsNoTracking()
            .Include(x => x.Certificate)
            .FirstOrDefaultAsync(x => x.Id == versionId, ct);
        if (v is null) return NotFound();

        var (content, suffix) = kind switch
        {
            "chain" => (v.PemChain, "chain.pem"),
            "fullchain" => (v.PemCertificate + "\n" + (v.PemChain ?? ""), "fullchain.pem"),
            _ => (v.PemCertificate, "crt.pem")
        };
        if (string.IsNullOrWhiteSpace(content))
            return NotFound(new ProblemDetails { Title = $"No {kind} material stored for this version." });

        var name = $"{v.Certificate.CommonName.Replace('*', '_')}-{v.SerialNumber}-{suffix}";
        return File(System.Text.Encoding.UTF8.GetBytes(content), "application/x-pem-file", name);
    }
}
