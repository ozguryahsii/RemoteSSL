using Microsoft.EntityFrameworkCore.Diagnostics;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Infrastructure.Persistence;

/// <summary>
/// Notices when a SaveChanges that carried audit rows failed, so the "audit pipeline
/// failure" alert of §32.3 can be raised. Every audit write path goes through
/// SaveChanges, so intercepting here covers them all without touching call sites.
/// </summary>
public class AuditPipelineInterceptor(AuditPipelineHealth health) : SaveChangesInterceptor
{
    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        Record(eventData);
        base.SaveChangesFailed(eventData);
    }

    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken ct = default)
    {
        Record(eventData);
        return base.SaveChangesFailedAsync(eventData, ct);
    }

    private void Record(DbContextErrorEventData eventData)
    {
        var context = eventData.Context;
        if (context is null) return;

        var audits = context.ChangeTracker.Entries<AuditEvent>()
            .Select(e => e.Entity.Action)
            .Distinct()
            .ToList();
        if (audits.Count == 0) return;

        health.RecordFailure(string.Join(", ", audits.Take(3)), eventData.Exception);
    }
}
