using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Api.Security;

/// <summary>
/// Binds each request to a tenant (design doc §35, ADR-008).
///
/// The tenant comes from the caller's own identity, never from anything the caller can choose: the
/// token's tenant claim, or failing that the user record behind the token. A header or query
/// parameter would let one tenant read another's data by simply asking, which is exactly what the
/// isolation is for. Requests with no identity — runner endpoints, health, the CA webhook — run
/// cross-tenant, because they are authenticated by their own means and address rows by id.
/// </summary>
public class TenantMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext http, ITenantContext tenants, RemoteSslDbContext db)
    {
        if (http.User.Identity?.IsAuthenticated != true)
        {
            // No user: platform-level or self-authenticating endpoint. It sees every tenant, which
            // is why those endpoints must address rows by id and never list.
            using var _ = tenants.EnterCrossTenant();
            await next(http);
            return;
        }

        var claim = http.User.FindFirstValue("tenant");
        if (Guid.TryParse(claim, out var fromClaim))
        {
            tenants.Enter(fromClaim);
            await next(http);
            return;
        }

        // A token without a tenant claim (a local account, or an identity provider that does not
        // send one) is resolved through the account record. That lookup itself must not be filtered.
        Guid? resolved;
        using (tenants.EnterCrossTenant())
        {
            var username = http.User.Identity!.Name;
            var subject = http.User.FindFirstValue(ClaimTypes.NameIdentifier);
            resolved = await db.Users.AsNoTracking()
                .Where(u => u.Username == username || (subject != null && u.ExternalSubject == subject))
                .Select(u => (Guid?)u.TenantId)
                .FirstOrDefaultAsync(http.RequestAborted);
        }

        tenants.Enter(resolved ?? Tenant.DefaultTenantId);
        await next(http);
    }
}

public static class TenantMiddlewareExtensions
{
    /// <summary>
    /// Registers tenant resolution. Must run after authentication — the tenant comes from the
    /// authenticated identity — and before anything that queries tenant-scoped data.
    /// </summary>
    public static IApplicationBuilder UseTenantContext(this IApplicationBuilder app) =>
        app.UseMiddleware<TenantMiddleware>();
}
