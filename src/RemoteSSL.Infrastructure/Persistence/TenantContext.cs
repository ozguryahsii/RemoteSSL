using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Infrastructure.Persistence;

/// <summary>
/// The scoped tenant context (design doc §35). Registered per request and per background scope, so
/// the tenant a query is filtered to is never ambient global state that another thread could
/// change underneath it.
/// </summary>
public class TenantContext : ITenantContext
{
    private Guid? _tenantId = Tenant.DefaultTenantId;

    public Guid? TenantId => CrossTenant ? null : _tenantId;
    public bool CrossTenant { get; private set; }

    public void Enter(Guid tenantId)
    {
        _tenantId = tenantId;
        CrossTenant = false;
    }

    public IDisposable EnterCrossTenant()
    {
        var previousTenant = _tenantId;
        var previousMode = CrossTenant;
        CrossTenant = true;
        return new Restore(this, previousTenant, previousMode);
    }

    private sealed class Restore(TenantContext context, Guid? tenantId, bool crossTenant) : IDisposable
    {
        public void Dispose()
        {
            context._tenantId = tenantId;
            context.CrossTenant = crossTenant;
        }
    }
}
