using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Tenants (design doc §35, ADR-008). Platform-level administration: the tenant list itself is not
/// tenant-scoped, because it is the scope. Every other screen shows one tenant's data only.
/// </summary>
[ApiController]
[Route("api/v1/tenants")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "Admin")]
public class TenantsController(
    RemoteSslDbContext db, ITenantContext tenants, AuditWriter audit) : ControllerBase
{
    public record CreateTenantRequest(string Name, string Slug);
    public record UpdateTenantRequest(string? Name, bool? Enabled);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct)
    {
        // Counts are read across tenants deliberately: this is the platform view.
        using var _ = tenants.EnterCrossTenant();
        return await db.Tenants.AsNoTracking()
            .OrderBy(t => t.Name)
            .Select(t => new
            {
                t.Id, t.Name, t.Slug, t.Enabled, t.CreatedAt,
                Certificates = db.Certificates.Count(c => c.TenantId == t.Id),
                Monitors = db.MonitorEndpoints.Count(m => m.TenantId == t.Id),
                Targets = db.Targets.Count(x => x.TenantId == t.Id),
                Users = db.Users.Count(u => u.TenantId == t.Id),
                IsCurrent = t.Id == Tenant.DefaultTenantId
            })
            .ToListAsync(ct);
    }

    /// <summary>Which tenant this caller's requests are filtered to.</summary>
    [HttpGet("current")]
    [Microsoft.AspNetCore.Authorization.Authorize]
    public async Task<ActionResult<object>> Current(CancellationToken ct)
    {
        var id = tenants.TenantId;
        if (id is null) return new { Id = (Guid?)null, Name = "All tenants", CrossTenant = true };

        using var _ = tenants.EnterCrossTenant();
        var tenant = await db.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        return tenant is null
            ? NotFound()
            : new { tenant.Id, tenant.Name, tenant.Slug, CrossTenant = false };
    }

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateTenantRequest req, CancellationToken ct)
    {
        using var _ = tenants.EnterCrossTenant();

        var slug = req.Slug.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(req.Name) || string.IsNullOrWhiteSpace(slug))
            return ValidationProblem("A tenant needs a name and a slug.");
        if (await db.Tenants.AnyAsync(t => t.Slug == slug, ct))
            return Conflict(new ProblemDetails { Title = $"A tenant with the slug '{slug}' already exists." });

        var tenant = new Tenant
        {
            Id = Guid.NewGuid(),
            Name = req.Name.Trim(),
            Slug = slug,
            Enabled = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.Tenants.Add(tenant);
        audit.Append(Actor(), "tenant.create", "tenant", tenant.Id.ToString(), "OK",
            new { tenant.Name, tenant.Slug });
        await db.SaveChangesAsync(ct);
        return new { tenant.Id, tenant.Name, tenant.Slug };
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateTenantRequest req, CancellationToken ct)
    {
        using var _ = tenants.EnterCrossTenant();
        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (tenant is null) return NotFound();

        if (!string.IsNullOrWhiteSpace(req.Name)) tenant.Name = req.Name.Trim();
        if (req.Enabled is { } enabled)
        {
            if (!enabled && id == Tenant.DefaultTenantId)
                return ValidationProblem("The default tenant cannot be disabled; it owns everything an upgrade brought over.");
            tenant.Enabled = enabled;
        }

        audit.Append(Actor(), "tenant.update", "tenant", id.ToString(), "OK", new { tenant.Name, tenant.Enabled });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    /// <summary>
    /// Removes an empty tenant. A tenant that still owns data is never deleted implicitly: doing so
    /// would either orphan rows or delete a customer's certificates as a side effect.
    /// </summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        if (id == Tenant.DefaultTenantId)
            return ValidationProblem("The default tenant cannot be removed.");

        using var _ = tenants.EnterCrossTenant();
        var tenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (tenant is null) return NotFound();

        var owned = await db.Certificates.CountAsync(c => c.TenantId == id, ct)
                    + await db.MonitorEndpoints.CountAsync(m => m.TenantId == id, ct)
                    + await db.Targets.CountAsync(t => t.TenantId == id, ct)
                    + await db.Users.CountAsync(u => u.TenantId == id, ct);
        if (owned > 0)
            return Conflict(new ProblemDetails
            {
                Title = $"This tenant still owns {owned} record(s); move or remove them before deleting it."
            });

        db.Tenants.Remove(tenant);
        audit.Append(Actor(), "tenant.delete", "tenant", id.ToString(), "OK", new { tenant.Name });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private string Actor() => User.Identity?.Name is { Length: > 0 } name ? $"user:{name}" : "user:api";
}
