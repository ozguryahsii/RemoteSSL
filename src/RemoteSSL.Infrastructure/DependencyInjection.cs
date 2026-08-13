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
        services.AddDbContext<RemoteSslDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("Database")));
        services.AddScoped<IRemoteSslDbContext>(sp => sp.GetRequiredService<RemoteSslDbContext>());

        services.AddSingleton<ITlsProber, TlsProber>();
        services.AddScoped<MonitorProbeService>();
        services.AddHostedService<ProbeSchedulerService>();
        services.AddHostedService<AutomationSchedulerService>();

        services.AddDataProtection();
        services.AddHttpClient();
        services.AddScoped<ISecretProtector, Security.DataProtectionSecretProtector>();
        services.AddScoped<Application.Auditing.AuditWriter>();
        services.AddScoped<Application.Certificates.InventoryService>();
        services.AddScoped<Application.Deployments.DeploymentService>();
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
