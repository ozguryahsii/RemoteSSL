namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// Which tenant the current unit of work belongs to (design doc §35, ADR-008).
///
/// Two modes, and the difference matters. A request runs <em>inside</em> a tenant, and every
/// tenant-scoped query is filtered to it. A background pass runs <em>across</em> tenants — a probe
/// scheduler must see every monitor — and says so explicitly by entering cross-tenant mode. There
/// is no third state: a query is either scoped to one tenant or deliberately unscoped.
/// </summary>
public interface ITenantContext
{
    /// <summary>The tenant in force, or null in cross-tenant mode.</summary>
    Guid? TenantId { get; }

    /// <summary>True when the filter is deliberately suspended for platform-wide work.</summary>
    bool CrossTenant { get; }

    /// <summary>Binds this unit of work to a tenant.</summary>
    void Enter(Guid tenantId);

    /// <summary>
    /// Suspends the tenant filter for platform work. Returns a scope that restores the previous
    /// state, so a background pass cannot leak cross-tenant access into whatever runs next.
    /// </summary>
    IDisposable EnterCrossTenant();
}
