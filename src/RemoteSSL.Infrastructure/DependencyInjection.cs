using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Monitoring;
using RemoteSSL.Infrastructure.Persistence;
using RemoteSSL.Infrastructure.Scheduling;
using RemoteSSL.Infrastructure.Tls;

namespace RemoteSSL.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddRemoteSslInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // Singleton: it records the audit writes the database could not persist (§32.3).
        services.AddSingleton<Application.Observability.AuditPipelineHealth>();
        services.AddSingleton<AuditPipelineInterceptor>();

        services.AddDbContext<RemoteSslDbContext>((sp, options) =>
            options.UseNpgsql(configuration.GetConnectionString("Database"))
                   .AddInterceptors(sp.GetRequiredService<AuditPipelineInterceptor>()));
        services.AddScoped<IRemoteSslDbContext>(sp => sp.GetRequiredService<RemoteSslDbContext>());

        services.AddSingleton<ITlsProber, TlsProber>();
        // The health check follows redirects but never enforces certificate validity — the TLS
        // probe already reports that, and failing here would hide the application's own state.
        services.AddHttpClient(Tls.HttpHealthChecker.ClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                AllowAutoRedirect = false
            });
        services.AddSingleton<Application.Monitoring.IHttpHealthChecker, Tls.HttpHealthChecker>();
        services.AddScoped<MonitorProbeService>();
        services.AddHostedService<ProbeSchedulerService>();
        services.AddHostedService<AutomationSchedulerService>();
        services.AddHostedService<MetricsRetentionService>();
        services.AddHostedService<ArtifactRetentionService>();

        services.AddDataProtection();
        services.AddHttpClient();
        services.AddScoped<ISecretProtector, Security.DataProtectionSecretProtector>();
        services.AddScoped<Application.Auditing.AuditWriter>();
        services.AddScoped<Application.Policies.GovernanceService>();
        services.AddScoped<Security.RunnerIdentityService>();
        services.AddScoped<Application.Observability.MetricsRecorder>();
        services.AddScoped<Application.Observability.MetricsQuery>();
        services.AddScoped<Application.Certificates.InventoryService>();
        services.AddScoped<Application.Deployments.DeploymentService>();
        services.AddScoped<Application.Deployments.DeploymentPlanner>();
        services.AddScoped<Application.Artifacts.ArtifactService>();
        // The S3 store only registers itself when a bucket is configured; without one the
        // artifact service keeps ciphertext in the database (§31.1).
        services.AddSingleton<Storage.S3ArtifactStore>();
        services.AddSingleton<Application.Artifacts.IArtifactObjectStore>(sp =>
            sp.GetRequiredService<Storage.S3ArtifactStore>());
        services.AddScoped<Application.Requests.CertificateRequestService>();
        services.AddScoped<Application.Requests.ICaConnectorResolver, Ca.DbCaConnectorResolver>();
        services.AddScoped<Application.Automation.AutomationService>();
        services.AddScoped<Ca.CaConnectorFactory>();
        services.AddSingleton<Notifications.WebhookNotificationService>();
        services.AddSingleton<Application.Abstractions.INotificationSink, Notifications.CompositeNotificationSink>();
        services.AddSingleton<Security.VaultSecretClient>();
        services.AddSingleton<Scheduling.PostgresLeaderLock>();

        return services;
    }
}
