using Microsoft.Extensions.DependencyInjection;
using RemoteSSL.Application.Abstractions;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Scopes for background work (design doc §35). A scheduler serves every tenant, so its scope
/// enters cross-tenant mode explicitly rather than inheriting whatever tenant happened to be last:
/// a probe sweep that silently saw one tenant's monitors would look like it was working.
/// </summary>
public static class BackgroundScope
{
    /// <summary>Creates a scope whose queries are not filtered to any single tenant.</summary>
    public static (IServiceScope Scope, IDisposable Tenancy) CreateCrossTenant(IServiceScopeFactory factory)
    {
        var scope = factory.CreateScope();
        var tenancy = scope.ServiceProvider.GetRequiredService<ITenantContext>().EnterCrossTenant();
        return (scope, tenancy);
    }
}
