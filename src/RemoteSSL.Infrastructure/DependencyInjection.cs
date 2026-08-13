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

        return services;
    }
}
