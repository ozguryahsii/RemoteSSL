using RemoteSSL.Application.Monitoring;
using RemoteSSL.Domain;

namespace RemoteSSL.Application.Policies;

/// <summary>
/// Resolves the lifecycle status of design doc §19.2. Expiry alone is not the whole story:
/// a certificate can be perfectly valid and still be PartiallyDeployed or DeploymentFailed,
/// and a revoked certificate stays revoked no matter how much validity is left. Deployment
/// and revocation states therefore take precedence over the expiry-derived health.
/// </summary>
public static class CertificateStatusResolver
{
    /// <summary>Statuses that describe the deployment/revocation reality rather than expiry.</summary>
    private static readonly CertificateHealthStatus[] Sticky =
    [
        CertificateHealthStatus.Revoked,
        CertificateHealthStatus.Superseded,
        CertificateHealthStatus.DeploymentFailed,
        CertificateHealthStatus.PartiallyDeployed,
        CertificateHealthStatus.PendingDeployment
    ];

    /// <summary>
    /// Expiry always wins once the certificate is actually expired — an expired certificate
    /// is an outage regardless of its deployment state. Otherwise a stored deployment or
    /// revocation state is shown, falling back to the expiry-derived health.
    /// </summary>
    public static CertificateHealthStatus Resolve(
        CertificateHealthStatus stored, DateTimeOffset? notAfter, DateTimeOffset now)
    {
        if (stored == CertificateHealthStatus.Revoked) return CertificateHealthStatus.Revoked;
        if (notAfter is null) return stored == default ? CertificateHealthStatus.Unknown : stored;

        var byExpiry = ExpiryCalculator.HealthFor(notAfter.Value, now);
        if (byExpiry == CertificateHealthStatus.Expired) return CertificateHealthStatus.Expired;

        return Sticky.Contains(stored) ? stored : byExpiry;
    }

    /// <summary>Deployment job outcome mapped onto the certificate's lifecycle status (§19.2).</summary>
    public static CertificateHealthStatus? FromDeployment(DeploymentJobStatus jobStatus) => jobStatus switch
    {
        DeploymentJobStatus.PendingApproval or DeploymentJobStatus.Approved
            or DeploymentJobStatus.Scheduled or DeploymentJobStatus.Running => CertificateHealthStatus.PendingDeployment,
        DeploymentJobStatus.PartiallyFailed => CertificateHealthStatus.PartiallyDeployed,
        DeploymentJobStatus.Failed or DeploymentJobStatus.RolledBack
            or DeploymentJobStatus.RollbackFailed => CertificateHealthStatus.DeploymentFailed,
        // A fully successful job leaves the status to expiry again.
        DeploymentJobStatus.Succeeded => CertificateHealthStatus.Healthy,
        _ => null
    };
}
