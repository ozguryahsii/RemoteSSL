using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Certificate policy administration (design doc §39 + the §17.2 request rules and the
/// §23.2/§23.3 governance switches). Exactly one policy is the default; certificates may
/// point at a different one.
/// </summary>
[ApiController]
[Route("api/v1/certificate-policies")]
[Authorize(Policy = "Admin")]
public class CertificatePoliciesController(IRemoteSslDbContext db, AuditWriter audit) : ControllerBase
{
    public record PolicyRequest(
        string Name,
        bool IsDefault = false,
        int MinimumRsaBits = 2048,
        List<string>? AllowedEcCurves = null,
        int RenewBeforeDays = 30,
        bool RotateKeyOnRenewal = true,
        List<string>? RequireApprovalIn = null,
        bool BlockWeakSignatureAlgorithms = true,
        bool RequirePostDeploymentProbe = true,
        bool AllowWildcard = true,
        int? MaxValidityDays = null,
        List<string>? AllowedDomainSuffixes = null,
        List<string>? BlockedDomainSuffixes = null,
        bool WarnOnOverlap = true,
        bool RequireOwner = false,
        List<string>? RequireWindowIn = null,
        bool EnforceSeparationOfDuties = true);

    // Named policy, not a bare [Authorize]: with authentication disabled for development
    // there is no scheme to challenge with, and a bare attribute would fail the request.
    [HttpGet]
    [Authorize(Policy = "CertOps")]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        (await db.CertificatePolicies.AsNoTracking().OrderByDescending(p => p.IsDefault)
            .ThenBy(p => p.Name).ToListAsync(ct))
        .Select(Project);

    [HttpPost]
    public async Task<ActionResult<object>> Create(PolicyRequest req, CancellationToken ct)
    {
        var policy = new CertificatePolicy
        {
            Id = Guid.NewGuid(),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        Apply(policy, req);
        db.CertificatePolicies.Add(policy);
        if (policy.IsDefault) await ClearOtherDefaultsAsync(policy.Id, ct);
        audit.Append("user:api", "certificate-policy.create", "certificate_policy", policy.Id.ToString(),
            "OK", new { policy.Name, policy.IsDefault });
        await db.SaveChangesAsync(ct);
        return new { policy.Id };
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, PolicyRequest req, CancellationToken ct)
    {
        var policy = await db.CertificatePolicies.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (policy is null) return NotFound();
        Apply(policy, req);
        policy.UpdatedAt = DateTimeOffset.UtcNow;
        if (policy.IsDefault) await ClearOtherDefaultsAsync(policy.Id, ct);
        audit.Append("user:api", "certificate-policy.update", "certificate_policy", id.ToString(),
            "OK", new { policy.Name, policy.IsDefault });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var policy = await db.CertificatePolicies.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (policy is null) return NotFound();
        if (policy.IsDefault)
            return Conflict(new ProblemDetails { Title = "The default policy cannot be deleted; make another one default first." });

        // Certificates pointing at this policy fall back to the default one.
        var attached = await db.Certificates.Where(c => c.CertificatePolicyId == id).ToListAsync(ct);
        foreach (var c in attached) c.CertificatePolicyId = null;

        db.CertificatePolicies.Remove(policy);
        audit.Append("user:api", "certificate-policy.delete", "certificate_policy", id.ToString(),
            "OK", new { policy.Name, detached = attached.Count });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private async Task ClearOtherDefaultsAsync(Guid keepId, CancellationToken ct)
    {
        var others = await db.CertificatePolicies.Where(p => p.IsDefault && p.Id != keepId).ToListAsync(ct);
        foreach (var o in others) o.IsDefault = false;
    }

    private static void Apply(CertificatePolicy policy, PolicyRequest req)
    {
        policy.Name = req.Name;
        policy.IsDefault = req.IsDefault;
        policy.MinimumRsaBits = req.MinimumRsaBits;
        policy.AllowedEcCurvesJson = Serialize(req.AllowedEcCurves, """["P-256","P-384"]""");
        policy.RenewBeforeDays = req.RenewBeforeDays;
        policy.RotateKeyOnRenewal = req.RotateKeyOnRenewal;
        policy.RequireApprovalInJson = Serialize(req.RequireApprovalIn, "[]");
        policy.BlockWeakSignatureAlgorithms = req.BlockWeakSignatureAlgorithms;
        policy.RequirePostDeploymentProbe = req.RequirePostDeploymentProbe;
        policy.AllowWildcard = req.AllowWildcard;
        policy.MaxValidityDays = req.MaxValidityDays;
        policy.AllowedDomainSuffixesJson = Serialize(req.AllowedDomainSuffixes, "[]");
        policy.BlockedDomainSuffixesJson = Serialize(req.BlockedDomainSuffixes, "[]");
        policy.WarnOnOverlap = req.WarnOnOverlap;
        policy.RequireOwner = req.RequireOwner;
        policy.RequireWindowInJson = Serialize(req.RequireWindowIn, "[]");
        policy.EnforceSeparationOfDuties = req.EnforceSeparationOfDuties;
    }

    private static string Serialize(List<string>? values, string fallback) =>
        values is null ? fallback : JsonSerializer.Serialize(values);

    private static object Project(CertificatePolicy p) => new
    {
        p.Id, p.Name, p.IsDefault,
        p.MinimumRsaBits,
        AllowedEcCurves = Parse(p.AllowedEcCurvesJson),
        p.RenewBeforeDays, p.RotateKeyOnRenewal,
        RequireApprovalIn = Parse(p.RequireApprovalInJson),
        p.BlockWeakSignatureAlgorithms, p.RequirePostDeploymentProbe,
        p.AllowWildcard, p.MaxValidityDays,
        AllowedDomainSuffixes = Parse(p.AllowedDomainSuffixesJson),
        BlockedDomainSuffixes = Parse(p.BlockedDomainSuffixesJson),
        p.WarnOnOverlap, p.RequireOwner,
        RequireWindowIn = Parse(p.RequireWindowInJson),
        p.EnforceSeparationOfDuties,
        p.CreatedAt, p.UpdatedAt
    };

    private static List<string> Parse(string json)
    {
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch (JsonException) { return []; }
    }

    /// <summary>Creates the §39 baseline policy on first start so governance is never undefined.</summary>
    public static async Task SeedDefaultAsync(IRemoteSslDbContext db, CancellationToken ct)
    {
        if (await db.CertificatePolicies.AnyAsync(ct)) return;
        db.CertificatePolicies.Add(new CertificatePolicy
        {
            Id = Guid.NewGuid(),
            Name = "Default certificate policy",
            IsDefault = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }
}
