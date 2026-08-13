using Microsoft.EntityFrameworkCore;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// Persistence abstraction so application services stay free of the concrete EF
/// context (and testable against the in-memory provider).
/// </summary>
public interface IRemoteSslDbContext
{
    DbSet<Certificate> Certificates { get; }
    DbSet<CertificateVersion> CertificateVersions { get; }
    DbSet<CertificateSan> CertificateSans { get; }
    DbSet<MonitorEndpoint> MonitorEndpoints { get; }
    DbSet<MonitorCertificateLink> MonitorCertificateLinks { get; }
    DbSet<Target> Targets { get; }
    DbSet<CertificateStore> CertificateStores { get; }
    DbSet<DeploymentBinding> DeploymentBindings { get; }
    DbSet<CredentialRef> CredentialRefs { get; }
    DbSet<DeploymentJob> DeploymentJobs { get; }
    DbSet<RunnerNode> Runners { get; }
    DbSet<AuditEvent> AuditEvents { get; }

    Task<int> SaveChangesAsync(CancellationToken ct = default);
}
