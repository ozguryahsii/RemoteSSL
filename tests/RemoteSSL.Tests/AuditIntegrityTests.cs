using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Artifacts;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>Audit hash chain, external copy and retention — design doc §25.3, ADR-007.</summary>
public class AuditIntegrityTests
{
    /// <summary>An object store that keeps what it was given, so the archive can be inspected.</summary>
    private sealed class MemoryStore(bool enabled = true) : IArtifactObjectStore
    {
        public Dictionary<string, byte[]> Objects { get; } = [];
        public string Provider => "memory";
        public bool Enabled => enabled;

        public Task PutAsync(string key, byte[] ciphertext, CancellationToken ct)
        {
            Objects[key] = ciphertext;
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string key, CancellationToken ct) => Task.FromResult(Objects[key]);
        public Task DeleteAsync(string key, CancellationToken ct) { Objects.Remove(key); return Task.CompletedTask; }
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"audit-tests-{Guid.NewGuid()}").Options);

    private static async Task WriteAsync(RemoteSslDbContext db, params string[] actions)
    {
        var writer = new AuditWriter(db);
        foreach (var action in actions)
            writer.Append("user:ozgur", action, "certificate", "1", "OK", new { note = action });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Sealing_links_every_row_to_its_predecessor()
    {
        using var db = CreateDb();
        await WriteAsync(db, "a", "b", "c");
        var chain = new AuditChain(db);

        Assert.Equal(3, await chain.SealAsync(100, default));

        var rows = await db.AuditEvents.OrderBy(e => e.Sequence).ToListAsync();
        Assert.Equal([1L, 2L, 3L], rows.Select(r => r.Sequence));
        Assert.Null(rows[0].PreviousHash);
        Assert.Equal(rows[0].Hash, rows[1].PreviousHash);
        Assert.Equal(rows[1].Hash, rows[2].PreviousHash);
        Assert.All(rows, r => Assert.NotNull(r.SealedAt));
    }

    [Fact]
    public async Task Sealing_is_idempotent_and_continues_where_it_left_off()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        await WriteAsync(db, "a", "b");
        await chain.SealAsync(100, default);

        Assert.Equal(0, await chain.SealAsync(100, default));

        await WriteAsync(db, "c");
        Assert.Equal(1, await chain.SealAsync(100, default));
        Assert.Equal(3, (await db.AuditEvents.OrderByDescending(e => e.Sequence).FirstAsync()).Sequence);
        Assert.True((await chain.VerifyAsync(default)).Intact);
    }

    [Fact]
    public async Task An_intact_chain_verifies_and_reports_unsealed_rows_separately()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        await WriteAsync(db, "a", "b");
        await chain.SealAsync(100, default);
        await WriteAsync(db, "c"); // written after the pass, not yet sealed

        var status = await chain.VerifyAsync(default);

        Assert.True(status.Intact);
        Assert.Equal(2, status.Sealed);
        Assert.Equal(1, status.Unsealed);
    }

    [Fact]
    public async Task Editing_a_sealed_row_breaks_the_chain()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        await WriteAsync(db, "a", "b", "c");
        await chain.SealAsync(100, default);

        var middle = await db.AuditEvents.FirstAsync(e => e.Sequence == 2);
        middle.Result = "TAMPERED";
        await db.SaveChangesAsync();

        var status = await chain.VerifyAsync(default);
        Assert.False(status.Intact);
        Assert.Equal(2, status.FirstBrokenSequence);
        Assert.Contains("modified after it was sealed", status.Detail);
    }

    [Fact]
    public async Task Removing_a_row_from_the_middle_breaks_the_chain()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        await WriteAsync(db, "a", "b", "c");
        await chain.SealAsync(100, default);

        db.AuditEvents.Remove(await db.AuditEvents.FirstAsync(e => e.Sequence == 2));
        await db.SaveChangesAsync();

        var status = await chain.VerifyAsync(default);
        Assert.False(status.Intact);
        Assert.Contains("missing or was reordered", status.Detail);
    }

    [Fact]
    public async Task The_hash_covers_the_request_context_so_it_cannot_be_rewritten_either()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        new AuditWriter(db, null, new AuditContext { SourceIp = "10.0.0.5", SessionId = "s1" })
            .Append("user:ozgur", "certificate.revoke", "certificate", "1", "OK");
        await db.SaveChangesAsync();
        await chain.SealAsync(100, default);

        var row = await db.AuditEvents.FirstAsync();
        Assert.Equal("10.0.0.5", row.SourceIp);
        row.SourceIp = "192.168.1.1";
        await db.SaveChangesAsync();

        Assert.False((await chain.VerifyAsync(default)).Intact);
    }

    [Fact]
    public async Task Archiving_writes_sealed_rows_out_and_marks_them()
    {
        using var db = CreateDb();
        var store = new MemoryStore();
        await WriteAsync(db, "a", "b");
        await new AuditChain(db).SealAsync(100, default);

        var result = await new AuditArchive(db, store, new AuditWriter(db)).ArchiveBatchAsync(100, default);

        Assert.Equal(2, result.Rows);
        Assert.NotNull(result.Key);
        Assert.Equal(1, result.FromSequence);
        Assert.Equal(2, result.ToSequence);

        var lines = System.Text.Encoding.UTF8.GetString(store.Objects[result.Key!])
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains("\"hash\"", lines[0]);

        Assert.Equal(2, await db.AuditEvents.CountAsync(e => e.ArchivedAt != null && e.Action != "audit.archive"));
    }

    [Fact]
    public async Task An_unsealed_row_is_not_archived()
    {
        using var db = CreateDb();
        var store = new MemoryStore();
        await WriteAsync(db, "a");

        var result = await new AuditArchive(db, store, new AuditWriter(db)).ArchiveBatchAsync(100, default);

        Assert.Equal(0, result.Rows);
        Assert.Empty(store.Objects);
    }

    [Fact]
    public async Task Archiving_without_an_object_store_says_so_rather_than_pretending()
    {
        using var db = CreateDb();
        var archive = new AuditArchive(db, new MemoryStore(enabled: false), new AuditWriter(db));

        Assert.False(archive.Available);
        await Assert.ThrowsAsync<InvalidOperationException>(() => archive.ArchiveBatchAsync(100, default));
    }

    [Fact]
    public async Task Retention_removes_only_the_old_archived_prefix()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        await WriteAsync(db, "old-1", "old-2", "recent");
        await chain.SealAsync(100, default);

        var now = DateTimeOffset.UtcNow;
        var rows = await db.AuditEvents.OrderBy(e => e.Sequence).ToListAsync();
        rows[0].Timestamp = now.AddDays(-400); rows[0].ArchivedAt = now;
        rows[1].Timestamp = now.AddDays(-400); rows[1].ArchivedAt = now;
        rows[2].Timestamp = now;
        await db.SaveChangesAsync();

        var purged = await new AuditRetention(db, new AuditWriter(db))
            .PurgeAsync(now.AddDays(-365), requireArchived: true, 100, default);

        Assert.Equal(2, purged);
        Assert.Equal("recent", (await db.AuditEvents.Where(e => e.Action != "audit.purge").SingleAsync()).Action);
    }

    [Fact]
    public async Task Retention_keeps_a_row_that_has_no_external_copy_however_old_it_is()
    {
        using var db = CreateDb();
        await WriteAsync(db, "old");
        await new AuditChain(db).SealAsync(100, default);
        var row = await db.AuditEvents.FirstAsync();
        row.Timestamp = DateTimeOffset.UtcNow.AddDays(-400);
        await db.SaveChangesAsync();

        var purged = await new AuditRetention(db, new AuditWriter(db))
            .PurgeAsync(DateTimeOffset.UtcNow.AddDays(-365), requireArchived: true, 100, default);

        Assert.Equal(0, purged);
    }

    [Fact]
    public async Task What_survives_retention_still_verifies_as_a_chain()
    {
        using var db = CreateDb();
        var chain = new AuditChain(db);
        await WriteAsync(db, "a", "b", "c", "d");
        await chain.SealAsync(100, default);

        var now = DateTimeOffset.UtcNow;
        foreach (var row in await db.AuditEvents.Where(e => e.Sequence <= 2).ToListAsync())
        {
            row.Timestamp = now.AddDays(-400);
            row.ArchivedAt = now;
        }
        await db.SaveChangesAsync();

        await new AuditRetention(db, new AuditWriter(db))
            .PurgeAsync(now.AddDays(-365), requireArchived: true, 100, default);
        await chain.SealAsync(100, default); // seal the purge's own audit row

        var status = await chain.VerifyAsync(default);
        Assert.True(status.Intact, status.Detail);
    }

    [Fact]
    public void The_canonical_form_separates_fields_so_they_cannot_be_shifted_between_columns()
    {
        // Without a separator, actor "ab" + action "c" would hash the same as "a" + "bc".
        var left = new AuditEvent { Actor = "ab", Action = "c" };
        var right = new AuditEvent { Actor = "a", Action = "bc" };

        Assert.NotEqual(AuditChain.ComputeHash(left, null), AuditChain.ComputeHash(right, null));
    }

    [Fact]
    public async Task The_siem_mirror_carries_the_request_context()
    {
        using var db = CreateDb();
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            [new KeyValuePair<string, string?>("Integrations:ForwardAuditToSiem", "true")]).Build();

        new AuditWriter(db, config, new AuditContext { SourceIp = "10.0.0.5", UserAgent = "curl/8" })
            .Append("user:ozgur", "certificate.revoke", "certificate", "1", "OK");
        await db.SaveChangesAsync();

        var payload = (await db.OutboxMessages.SingleAsync()).PayloadJson;
        Assert.Contains("10.0.0.5", payload);
        Assert.Contains("curl/8", payload);
    }
}
