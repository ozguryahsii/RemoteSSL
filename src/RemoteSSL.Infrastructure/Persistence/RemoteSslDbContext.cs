using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Infrastructure.Persistence;

public class RemoteSslDbContext(DbContextOptions<RemoteSslDbContext> options) : DbContext(options), IRemoteSslDbContext
{
    public DbSet<Certificate> Certificates => Set<Certificate>();
    public DbSet<CertificateVersion> CertificateVersions => Set<CertificateVersion>();
    public DbSet<CertificateSan> CertificateSans => Set<CertificateSan>();
    public DbSet<MonitorEndpoint> MonitorEndpoints => Set<MonitorEndpoint>();
    public DbSet<MonitorCertificateLink> MonitorCertificateLinks => Set<MonitorCertificateLink>();
    public DbSet<Target> Targets => Set<Target>();
    public DbSet<CertificateStore> CertificateStores => Set<CertificateStore>();
    public DbSet<DeploymentBinding> DeploymentBindings => Set<DeploymentBinding>();
    public DbSet<CredentialRef> CredentialRefs => Set<CredentialRef>();
    public DbSet<DeploymentJob> DeploymentJobs => Set<DeploymentJob>();
    public DbSet<DeploymentJobTarget> DeploymentJobTargets => Set<DeploymentJobTarget>();
    public DbSet<DeploymentStep> DeploymentSteps => Set<DeploymentStep>();
    public DbSet<RunnerNode> Runners => Set<RunnerNode>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<RunnerJob> RunnerJobs => Set<RunnerJob>();
    public DbSet<CaConnectorConfig> CaConnectors => Set<CaConnectorConfig>();
    public DbSet<CertificateRequestEntity> CertificateRequests => Set<CertificateRequestEntity>();
    public DbSet<RenewalPolicy> RenewalPolicies => Set<RenewalPolicy>();
    public DbSet<ApprovalRequest> ApprovalRequests => Set<ApprovalRequest>();
    public DbSet<UserAccount> Users => Set<UserAccount>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Certificate>(e =>
        {
            e.Property(x => x.CommonName).HasMaxLength(512);
            e.Property(x => x.DisplayName).HasMaxLength(512);
            e.HasIndex(x => x.CommonName);
        });

        b.Entity<CertificateVersion>(e =>
        {
            e.Property(x => x.SerialNumber).HasMaxLength(128);
            e.Property(x => x.Sha256Thumbprint).HasMaxLength(64);
            e.Property(x => x.Sha1Thumbprint).HasMaxLength(40);
            // Inventory correlation happens on thumbprint and issuer+serial.
            e.HasIndex(x => x.Sha256Thumbprint).IsUnique();
            e.HasIndex(x => new { x.IssuerDn, x.SerialNumber });
            e.HasIndex(x => x.NotAfter);
            e.HasOne(x => x.Certificate).WithMany(x => x.Versions).HasForeignKey(x => x.CertificateId);
        });

        b.Entity<CertificateSan>(e =>
        {
            e.Property(x => x.Value).HasMaxLength(512);
            e.HasIndex(x => x.Value);
            e.HasOne(x => x.CertificateVersion).WithMany(x => x.Sans).HasForeignKey(x => x.CertificateVersionId);
        });

        b.Entity<MonitorEndpoint>(e =>
        {
            e.Property(x => x.Host).HasMaxLength(512);
            e.Property(x => x.Sni).HasMaxLength(512);
            e.HasIndex(x => new { x.Host, x.Port, x.Sni }).IsUnique();
            e.HasOne(x => x.LastObservedVersion).WithMany().HasForeignKey(x => x.LastObservedVersionId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<MonitorCertificateLink>(e =>
        {
            e.HasKey(x => new { x.MonitorEndpointId, x.CertificateId });
            e.HasOne(x => x.MonitorEndpoint).WithMany(x => x.CertificateLinks).HasForeignKey(x => x.MonitorEndpointId);
            e.HasOne(x => x.Certificate).WithMany(x => x.MonitorLinks).HasForeignKey(x => x.CertificateId);
        });

        b.Entity<Target>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(256);
            e.Property(x => x.AdapterType).HasMaxLength(64);
            e.Property(x => x.ConnectionConfigJson).HasColumnType("jsonb");
            e.HasIndex(x => x.Name).IsUnique();
        });

        b.Entity<CertificateStore>(e =>
        {
            e.Property(x => x.StoreType).HasMaxLength(64);
            e.Property(x => x.StorePath).HasMaxLength(1024);
            e.Property(x => x.ConfigJson).HasColumnType("jsonb");
            e.HasOne(x => x.Target).WithMany(x => x.Stores).HasForeignKey(x => x.TargetId);
        });

        b.Entity<DeploymentBinding>(e =>
        {
            e.Property(x => x.ServiceBindingJson).HasColumnType("jsonb");
            e.Property(x => x.ActivationPolicyJson).HasColumnType("jsonb");
            e.HasOne(x => x.CertificateStore).WithMany(x => x.Bindings).HasForeignKey(x => x.CertificateStoreId);
        });

        b.Entity<CredentialRef>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(256);
            e.Property(x => x.SecretIdentifier).HasMaxLength(1024);
            e.Property(x => x.AccessPolicyJson).HasColumnType("jsonb");
        });

        b.Entity<DeploymentJob>(e =>
        {
            e.Property(x => x.Strategy).HasMaxLength(64);
            e.Property(x => x.CorrelationId).HasMaxLength(64);
            e.HasIndex(x => x.CorrelationId);
        });

        b.Entity<DeploymentJobTarget>(e =>
        {
            e.HasOne(x => x.DeploymentJob).WithMany(x => x.Targets).HasForeignKey(x => x.DeploymentJobId);
        });

        b.Entity<DeploymentStep>(e =>
        {
            e.Property(x => x.IdempotencyKey).HasMaxLength(128);
            e.HasOne(x => x.DeploymentJobTarget).WithMany(x => x.Steps).HasForeignKey(x => x.DeploymentJobTargetId);
        });

        b.Entity<RunnerNode>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(256);
            e.Property(x => x.CapabilitiesJson).HasColumnType("jsonb");
        });

        b.Entity<RunnerJob>(e =>
        {
            e.Property(x => x.JobType).HasMaxLength(64);
            e.Property(x => x.Status).HasMaxLength(32);
            e.Property(x => x.PayloadJson).HasColumnType("jsonb");
            e.HasIndex(x => new { x.Status, x.RunnerId });
        });
        b.Entity<CaConnectorConfig>(e =>
        {
            e.Property(x => x.Name).HasMaxLength(256);
            e.Property(x => x.ConnectorType).HasMaxLength(64);
        });
        b.Entity<CertificateRequestEntity>(e =>
        {
            e.Property(x => x.CommonName).HasMaxLength(512);
            e.HasIndex(x => x.State);
        });
        b.Entity<UserAccount>(e => e.HasIndex(x => x.Username).IsUnique());

        b.Entity<AuditEvent>(e =>
        {
            e.Property(x => x.Actor).HasMaxLength(256);
            e.Property(x => x.Action).HasMaxLength(128);
            e.Property(x => x.ObjectType).HasMaxLength(128);
            e.Property(x => x.CorrelationId).HasMaxLength(64);
            e.Property(x => x.DetailsJson).HasColumnType("jsonb");
            e.HasIndex(x => x.Timestamp);
            e.HasIndex(x => x.CorrelationId);
        });
    }
}
