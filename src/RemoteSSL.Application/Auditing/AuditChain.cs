using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Auditing;

/// <summary>The outcome of walking the chain (design doc §25.3).</summary>
/// <param name="Sealed">How many rows carry a hash.</param>
/// <param name="Unsealed">Rows written but not yet sealed; they are simply newer than the last pass.</param>
/// <param name="Intact">False when any link fails to verify.</param>
/// <param name="FirstBrokenSequence">Where the chain first fails, if it does.</param>
public sealed record AuditChainStatus(
    long Sealed, long Unsealed, bool Intact, long? FirstBrokenSequence, string? Detail, string? HeadHash);

/// <summary>
/// The tamper-evidence chain over the audit log (design doc §25.3, ADR-007). Rows are hashed in
/// insertion order, each over its own content plus the previous row's hash; changing or removing
/// a row in the middle therefore breaks every link after it.
///
/// Sealing runs as a background pass rather than at insert time. That keeps concurrent writers
/// from serialising on a single chain head, and the ordering it relies on — the monotonic row id —
/// is assigned by the database itself.
/// </summary>
public class AuditChain(IRemoteSslDbContext db)
{
    /// <summary>ASCII unit separator — a byte no field value contains, so fields cannot blur together.</summary>
    private const string FieldSeparator = "\u001f";

    /// <summary>
    /// The canonical form a row is hashed in. Field order and separators are part of the contract:
    /// changing them would invalidate every previously sealed row.
    /// </summary>
    public static string Canonicalize(AuditEvent e, string? previousHash) => string.Join(FieldSeparator,
        e.Id.ToString(CultureInfo.InvariantCulture),
        e.Timestamp.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        e.Actor, e.Action, e.ObjectType, e.ObjectId ?? "",
        e.TargetId?.ToString() ?? "", e.Result, e.CorrelationId, e.DetailsJson,
        e.SessionId ?? "", e.SourceIp ?? "", e.UserAgent ?? "", e.ApprovalReference ?? "",
        e.OldFingerprint ?? "", e.NewFingerprint ?? "",
        previousHash ?? "");

    public static string ComputeHash(AuditEvent e, string? previousHash) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonicalize(e, previousHash))));

    /// <summary>
    /// Seals every row written since the last pass. Returns how many were sealed. Safe to run
    /// repeatedly; rows that already carry a hash are left exactly as they are.
    /// </summary>
    public async Task<int> SealAsync(int batchSize, CancellationToken ct)
    {
        var head = await db.AuditEvents.AsNoTracking()
            .Where(e => e.Hash != null)
            .OrderByDescending(e => e.Sequence)
            .Select(e => new { e.Sequence, e.Hash })
            .FirstOrDefaultAsync(ct);

        var sequence = head?.Sequence ?? 0;
        var previousHash = head?.Hash;

        var pending = await db.AuditEvents
            .Where(e => e.Hash == null)
            .OrderBy(e => e.Id)
            .Take(batchSize)
            .ToListAsync(ct);
        if (pending.Count == 0) return 0;

        var now = DateTimeOffset.UtcNow;
        foreach (var row in pending)
        {
            row.Sequence = ++sequence;
            row.PreviousHash = previousHash;
            row.Hash = ComputeHash(row, previousHash);
            row.SealedAt = now;
            previousHash = row.Hash;
        }

        await db.SaveChangesAsync(ct);
        return pending.Count;
    }

    /// <summary>
    /// Walks the sealed chain and reports the first place it stops adding up — a changed field, a
    /// deleted row, or a re-ordered one all show up the same way: the recomputed hash no longer
    /// matches what is stored.
    /// </summary>
    public async Task<AuditChainStatus> VerifyAsync(CancellationToken ct)
    {
        var unsealed = await db.AuditEvents.CountAsync(e => e.Hash == null, ct);

        // Verification starts at the oldest surviving row, not at sequence 1: retention removes a
        // contiguous prefix, and what is left is still a valid chain from where it now begins.
        var first = await db.AuditEvents.AsNoTracking()
            .Where(e => e.Hash != null)
            .OrderBy(e => e.Sequence)
            .Select(e => new { e.Sequence, e.PreviousHash })
            .FirstOrDefaultAsync(ct);
        if (first is null) return new AuditChainStatus(0, unsealed, true, null, null, null);

        var previousHash = first.PreviousHash;
        var expectedSequence = first.Sequence - 1;
        long sealedCount = 0;
        const int page = 1000;
        long lastId = 0;

        while (true)
        {
            var batch = await db.AuditEvents.AsNoTracking()
                .Where(e => e.Hash != null && e.Id > lastId)
                .OrderBy(e => e.Id)
                .Take(page)
                .ToListAsync(ct);
            if (batch.Count == 0) break;

            foreach (var row in batch)
            {
                lastId = row.Id;
                expectedSequence++;
                sealedCount++;

                if (row.Sequence != expectedSequence)
                    return new AuditChainStatus(sealedCount, unsealed, false, row.Sequence,
                        $"Row {row.Id} carries sequence {row.Sequence} where {expectedSequence} was expected — "
                        + "a row is missing or was reordered.", previousHash);

                if (row.PreviousHash != previousHash)
                    return new AuditChainStatus(sealedCount, unsealed, false, row.Sequence,
                        $"Row {row.Id} does not link to its predecessor.", previousHash);

                var recomputed = ComputeHash(row, previousHash);
                if (recomputed != row.Hash)
                    return new AuditChainStatus(sealedCount, unsealed, false, row.Sequence,
                        $"Row {row.Id} was modified after it was sealed.", previousHash);

                previousHash = row.Hash;
            }
        }

        return new AuditChainStatus(sealedCount, unsealed, true, null, null, previousHash);
    }
}
