using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Artifacts;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Auditing;

/// <summary>What one archive pass produced.</summary>
/// <param name="Key">Object key the batch was written under, or null when nothing was due.</param>
public sealed record AuditArchiveResult(int Rows, string? Key, string? Sha256, long? FromSequence, long? ToSequence);

/// <summary>
/// Writes sealed audit rows to an external, write-once copy (design doc §25.3). The copy is what
/// survives an attacker with database access: the rows go to object storage where the bucket's
/// object-lock retention makes them immutable, and each batch carries its own digest plus the
/// chain hashes, so the export can be verified against the live chain later.
///
/// Only sealed rows are archived. An unsealed row has no place in the chain yet, and archiving it
/// would produce a copy that cannot be verified.
/// </summary>
public class AuditArchive(IRemoteSslDbContext db, IArtifactObjectStore store, AuditWriter audit)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>True when there is somewhere to put the copy; without it archiving is skipped.</summary>
    public bool Available => store.Enabled;

    /// <summary>
    /// Exports the next batch of sealed, not-yet-archived rows as JSON Lines. Returns what it
    /// wrote; a batch of zero rows means everything sealed has already been archived.
    /// </summary>
    public async Task<AuditArchiveResult> ArchiveBatchAsync(int batchSize, CancellationToken ct)
    {
        if (!Available)
            throw new InvalidOperationException(
                "No object store is configured, so the audit log has no external copy (Storage:S3:BucketName).");

        var rows = await db.AuditEvents
            .Where(e => e.Hash != null && e.ArchivedAt == null)
            .OrderBy(e => e.Sequence)
            .Take(batchSize)
            .ToListAsync(ct);
        if (rows.Count == 0) return new AuditArchiveResult(0, null, null, null, null);

        var body = new StringBuilder();
        foreach (var row in rows) body.Append(JsonSerializer.Serialize(Export(row), Json)).Append('\n');
        var bytes = Encoding.UTF8.GetBytes(body.ToString());
        var digest = Convert.ToHexString(SHA256.HashData(bytes));

        var from = rows[0].Sequence;
        var to = rows[^1].Sequence;
        var key = $"audit/{rows[0].Timestamp.ToUniversalTime():yyyy/MM/dd}/"
                  + $"{from.ToString("D12", CultureInfo.InvariantCulture)}-{to.ToString("D12", CultureInfo.InvariantCulture)}.jsonl";

        await store.PutAsync(key, bytes, ct);

        var now = DateTimeOffset.UtcNow;
        foreach (var row in rows) row.ArchivedAt = now;

        // The archive operation is itself auditable: it says exactly which rows left the system.
        audit.Append("service:audit-archive", "audit.archive", "audit_batch", key, "OK",
            new { rows = rows.Count, fromSequence = from, toSequence = to, sha256 = digest });
        await db.SaveChangesAsync(ct);

        return new AuditArchiveResult(rows.Count, key, digest, from, to);
    }

    /// <summary>The exported shape — the row as stored, plus the chain fields that prove its place.</summary>
    private static object Export(AuditEvent e) => new
    {
        e.Id, e.Sequence, e.Timestamp, e.Actor, e.Action, e.ObjectType, e.ObjectId, e.TargetId,
        e.Result, e.CorrelationId, e.DetailsJson, e.SessionId, e.SourceIp, e.UserAgent,
        e.ApprovalReference, e.OldFingerprint, e.NewFingerprint,
        e.PreviousHash, e.Hash, e.SealedAt
    };
}

/// <summary>
/// Audit retention (design doc §25.3). Rows leave only because the retention period elapsed, and
/// only after the external copy exists — deleting evidence that was never archived would defeat
/// the point of keeping it. Deletion is itself audited, with the sequence range it removed.
/// </summary>
public class AuditRetention(IRemoteSslDbContext db, AuditWriter audit)
{
    /// <summary>
    /// Removes rows older than the retention period. When <paramref name="requireArchived"/> is
    /// true — which it is whenever an object store is configured — a row that has no external copy
    /// is kept regardless of its age.
    /// </summary>
    public async Task<int> PurgeAsync(DateTimeOffset olderThan, bool requireArchived, int batchSize,
        CancellationToken ct)
    {
        var due = await db.AuditEvents
            .Where(e => e.Timestamp < olderThan
                        && e.Hash != null
                        && (!requireArchived || e.ArchivedAt != null))
            .OrderBy(e => e.Sequence)
            .Take(batchSize)
            .ToListAsync(ct);
        if (due.Count == 0) return 0;

        // Only a contiguous prefix may go: removing rows from the middle would break the chain for
        // everything after them, and the remaining log would read as tampered with.
        var head = await db.AuditEvents.Where(e => e.Hash != null)
            .OrderBy(e => e.Sequence).Select(e => e.Sequence).FirstAsync(ct);
        var contiguous = new List<AuditEvent>();
        var expected = head;
        foreach (var row in due)
        {
            if (row.Sequence != expected) break;
            contiguous.Add(row);
            expected++;
        }
        if (contiguous.Count == 0) return 0;

        db.AuditEvents.RemoveRange(contiguous);
        audit.Append("service:audit-retention", "audit.purge", "audit_batch", null, "OK", new
        {
            rows = contiguous.Count,
            fromSequence = contiguous[0].Sequence,
            toSequence = contiguous[^1].Sequence,
            olderThan
        });
        await db.SaveChangesAsync(ct);
        return contiguous.Count;
    }
}
