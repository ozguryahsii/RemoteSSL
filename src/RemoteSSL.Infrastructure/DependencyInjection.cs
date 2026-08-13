using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddRemoteSslInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<RemoteSslDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("Database")));

        return services;
    }
}
