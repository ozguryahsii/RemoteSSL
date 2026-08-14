namespace RemoteSSL.Domain.Entities;

/// <summary>
/// An entity that belongs to exactly one tenant (design doc §35, ADR-008). Implementing this is
/// what makes the query filter apply: nothing else marks a row as tenant-owned, so an entity that
/// forgets the interface would silently be visible to everyone.
/// </summary>
public interface ITenantScoped
{
    Guid TenantId { get; set; }
}

/// <summary>
/// An organization the platform serves (design doc §35). Tenancy here is isolation, not just
/// labelling: every tenant-scoped query is filtered at the database level, so one tenant's
/// certificates, targets and credentials cannot appear in another's screens even by mistake.
/// </summary>
public class Tenant
{
    /// <summary>
    /// The tenant every pre-existing row belongs to. Fixed rather than generated, so an upgrade of
    /// a single-tenant install can backfill deterministically and stay reproducible.
    /// </summary>
    public static readonly Guid DefaultTenantId = new("00000000-0000-0000-0000-00000000d001");

    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    /// <summary>Short stable identifier used in tokens and URLs, e.g. "acme".</summary>
    public string Slug { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}
