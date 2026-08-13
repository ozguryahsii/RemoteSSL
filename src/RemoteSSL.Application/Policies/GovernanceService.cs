using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Policies;

/// <summary>
/// Resolves which certificate policy applies and answers the governance questions of
/// §23.2/§23.3 that both the request wizard and the deployment orchestrator need.
/// </summary>
public class GovernanceService(IRemoteSslDbContext db)
{
    /// <summary>Fallback used when no policy row exists yet — the §39 defaults.</summary>
    public static CertificatePolicy Fallback { get; } = new()
    {
        Id = Guid.Empty,
        Name = "built-in default",
        IsDefault = true
    };

    /// <summary>Policy attached to the certificate, else the default row, else the built-in defaults.</summary>
    public async Task<CertificatePolicy> ResolveAsync(Guid? certificateId, CancellationToken ct)
    {
        if (certificateId is { } id)
        {
            var attached = await db.Certificates.AsNoTracking()
                .Where(c => c.Id == id && c.CertificatePolicyId != null)
                .Select(c => c.CertificatePolicyId!.Value)
                .FirstOrDefaultAsync(ct);
            if (attached != Guid.Empty)
            {
                var policy = await db.CertificatePolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == attached, ct);
                if (policy is not null) return policy;
            }
        }

        return await db.CertificatePolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct)
               ?? await db.CertificatePolicies.AsNoTracking().OrderBy(p => p.CreatedAt).FirstOrDefaultAsync(ct)
               ?? Fallback;
    }

    /// <summary>Names already covered by another certificate in the inventory (§17.2 overlap warning).</summary>
    public async Task<IReadOnlyList<string>> FindOverlappingAsync(
        IReadOnlyList<string> names, Guid? excludeCertificateId, CancellationToken ct)
    {
        if (names.Count == 0) return [];
        var byCommonName = await db.Certificates.AsNoTracking()
            .Where(c => names.Contains(c.CommonName.ToLower()) && c.Id != excludeCertificateId)
            .Select(c => c.CommonName)
            .ToListAsync(ct);

        var bySan = await db.CertificateSans.AsNoTracking()
            .Where(s => names.Contains(s.Value.ToLower())
                        && s.CertificateVersion.CertificateId != excludeCertificateId)
            .Select(s => s.CertificateVersion.Certificate.CommonName)
            .Distinct()
            .ToListAsync(ct);

        return byCommonName.Concat(bySan).Distinct().ToList();
    }

    /// <summary>
    /// Decides whether an approver may decide this change (§23.3). Break-glass administrators
    /// may override separation of duties; the caller must record that in the audit trail.
    /// </summary>
    public static ApproverDecision CheckApprover(
        CertificatePolicy policy, string? requestedBy, string approver, bool approverIsBreakGlass)
    {
        if (!PolicyEvaluator.IsSelfApproval(policy, requestedBy, approver)) return ApproverDecision.Allowed;
        return approverIsBreakGlass ? ApproverDecision.BreakGlass : ApproverDecision.SelfApprovalRefused;
    }
}

public enum ApproverDecision
{
    Allowed = 0,
    /// <summary>Requester approving their own change without break-glass — refuse.</summary>
    SelfApprovalRefused,
    /// <summary>Self-approval permitted because the approver holds the break-glass role; audit it.</summary>
    BreakGlass
}
