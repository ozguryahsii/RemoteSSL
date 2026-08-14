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
        // §25.1: request context for audit rows, filled per request by the API middleware.
        services.AddScoped<Application.Auditing.AuditContext>();
        // §25.3 integrity: hash chain, external WORM copy and retention, all leader-elected.
        services.AddScoped<Application.Auditing.AuditChain>();
        services.AddScoped<Application.Auditing.AuditArchive>();
        services.AddScoped<Application.Auditing.AuditRetention>();
        services.AddHostedService<Scheduling.AuditIntegrityService>();
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
        // §28.2 transactional outbox: notifying writes a row in the caller's own transaction, and
        // the dispatcher below delivers it afterwards to every channel that wants it.
        services.AddScoped<Application.Abstractions.INotificationSink, Application.Events.OutboxNotificationSink>();
        services.AddScoped<Application.Events.OutboxNotificationSink>();
        services.AddScoped<Application.Events.OutboxDispatcher>();
        services.AddSingleton<Application.Observability.NotificationHealth>();
        services.AddHostedService<Scheduling.OutboxDispatcherService>();

        // §33 delivery channels. Each reports itself disabled until configured, so an unconfigured
        // integration is skipped rather than retried forever.
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.WebhookChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.TeamsChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.EmailChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.RabbitMqChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.SyslogChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.SplunkHecChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.ServiceNowChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.PagerDutyChannel>();
        services.AddSingleton<Application.Abstractions.INotificationChannel, Notifications.OpsgenieChannel>();
        services.AddSingleton<Security.VaultSecretClient>();

        // Secret providers (§7.2). All three register unconditionally; each reports itself as
        // disabled until its configuration is present, so the broker refuses cleanly rather than
        // failing halfway through a deployment.
        services.AddSingleton<Application.Abstractions.ISecretProvider, Security.VaultSecretProvider>();
        services.AddSingleton<Application.Abstractions.ISecretProvider, Security.CyberArkSecretProvider>();
        services.AddSingleton<Application.Abstractions.ISecretProvider, Security.AzureKeyVaultSecretProvider>();
        services.AddScoped<Application.Security.SecretBroker>();
        services.AddHostedService<Scheduling.SecretRotationService>();

        // Key providers (§16.3): software always, token/cloud only where configured.
        services.AddSingleton<Application.Abstractions.IKeyProvider, Security.SoftwareKeyProvider>();
        services.AddSingleton<Application.Abstractions.IKeyProvider, Security.Pkcs11KeyProvider>();
        services.AddSingleton<Application.Abstractions.IKeyProvider, Security.CloudKmsKeyProvider>();
        services.AddScoped<Application.Security.ManagedKeyService>();

        services.AddSingleton<Scheduling.PostgresLeaderLock>();

        return services;
    }
}
