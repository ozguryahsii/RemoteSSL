using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;
using Xunit.Abstractions;

namespace RemoteSSL.Tests;

/// <summary>
/// Scale tests against a real PostgreSQL (design doc §36.1 performance, NFR-004).
///
/// These answer the question the architecture claims to have solved: at ten thousand endpoints,
/// does the scheduler still pick its next batch quickly, and does the batch stay bounded? An
/// in-memory provider cannot answer that — it has no query planner and no index — so this suite
/// only runs when a database is pointed at it:
///
///   REMOTESSL_PERF_DB="Host=localhost;Database=remotessl_perf;Username=remotessl;Password=..."
///
/// Without it the tests skip, so the normal build stays hermetic and fast.
/// </summary>
public class ScaleTests(ITestOutputHelper output)
{
    private const int Endpoints = 10_000;

    private static string? ConnectionString => Environment.GetEnvironmentVariable("REMOTESSL_PERF_DB");

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseNpgsql(ConnectionString)
            .Options);

    /// <summary>
    /// Seeds the endpoint inventory once per run. Uses raw SQL: ten thousand tracked entities would
    /// measure EF's change tracker rather than the query this test is about.
    /// </summary>
    private static async Task<RemoteSslDbContext> SeededAsync()
    {
        var db = CreateDb();
        await db.Database.EnsureDeletedAsync();
        await db.Database.MigrateAsync();

        await db.Database.ExecuteSqlRawAsync($"""
            INSERT INTO "MonitorEndpoints"
                ("Id", "TenantId", "Host", "Port", "Enabled", "ExternalProbeEnabled",
                 "LastProbeStatus", "InternalProbeStatus", "Protocol", "HealthCheckStatus",
                 "CreatedAt", "UpdatedAt", "LastProbeAt", "RetryCount")
            SELECT gen_random_uuid(),
                   '{Tenant.DefaultTenantId}',
                   'host-' || i || '.example.com',
                   443, true, true, 0, 0, 'tls', 'NotConfigured', now(), now(),
                   -- Most are overdue, spread over the last day; the rest were probed recently.
                   CASE WHEN i % 3 = 0 THEN now() - interval '5 minutes'
                        ELSE now() - (interval '1 minute' * (i % 1440)) - interval '2 hours' END,
                   1
            FROM generate_series(1, {Endpoints}) AS i;
            """);

        // A bulk insert leaves the planner with the statistics of an empty table, so it would
        // choose a sequential scan no matter how good the index is. Autovacuum does this in
        // production; doing it here measures the steady state rather than the seconds after a load.
        await db.Database.ExecuteSqlRawAsync("""ANALYZE "MonitorEndpoints";""");
        return db;
    }

    private bool Skip()
    {
        if (!string.IsNullOrWhiteSpace(ConnectionString)) return false;
        output.WriteLine("REMOTESSL_PERF_DB is not set; skipping the scale test.");
        return true;
    }

    [Fact]
    public async Task The_due_query_stays_fast_and_bounded_at_ten_thousand_endpoints()
    {
        if (Skip()) return;
        await using var db = await SeededAsync();

        Assert.Equal(Endpoints, await db.MonitorEndpoints.CountAsync());

        const int batchSize = 500;
        var now = DateTimeOffset.UtcNow;

        // Warm the plan cache so the measurement is of the steady state, not the first parse.
        _ = await DueBatch(db, now, batchSize);

        var stopwatch = Stopwatch.StartNew();
        var batch = await DueBatch(db, now, batchSize);
        stopwatch.Stop();

        output.WriteLine($"due batch of {batch.Count} selected from {Endpoints} endpoints "
                         + $"in {stopwatch.ElapsedMilliseconds} ms");

        // The batch is what bounds memory and tick duration; it must not grow with the inventory.
        Assert.Equal(batchSize, batch.Count);
        // Generous by design: this is a regression guard against a sequential scan creeping in,
        // not a benchmark of the machine it runs on.
        Assert.True(stopwatch.ElapsedMilliseconds < 1000,
            $"the due query took {stopwatch.ElapsedMilliseconds} ms; an index is probably missing");
    }

    [Fact]
    public async Task The_due_query_uses_the_index_rather_than_scanning_the_table()
    {
        if (Skip()) return;
        await using var db = await SeededAsync();

        // A plan test that explains different SQL than the code runs proves nothing, so first
        // check EF's actual translation for the two things the plan depends on: an ordering on
        // the bare column, and no computed sort key that would match no index.
        var overdueSql = OverdueQuery(db, DateTimeOffset.UtcNow, 500).ToQueryString();
        output.WriteLine(overdueSql);
        Assert.Contains("""ORDER BY m."LastProbeAt" """.TrimEnd(), overdueSql);
        Assert.DoesNotContain("COALESCE", overdueSql, StringComparison.OrdinalIgnoreCase);

        // EXPLAIN takes literals because ToQueryString leaves @__p placeholders unbound.
        foreach (var (half, sql) in new (string, string)[]
                 {
                     ("never probed", """
                        SELECT "Id" FROM "MonitorEndpoints"
                        WHERE "Enabled" AND "LastProbeAt" IS NULL
                        LIMIT 500;
                        """),
                     ("overdue", """
                        SELECT "Id" FROM "MonitorEndpoints"
                        WHERE "Enabled" AND "LastProbeAt" IS NOT NULL
                          AND "LastProbeAt" < now() - interval '60 minutes'
                        ORDER BY "LastProbeAt"
                        LIMIT 500;
                        """)
                 })
        {
            var plan = await ExplainAsync(db, sql);
            output.WriteLine($"--- {half} ---\n{plan}");

            // The (Enabled, LastProbeAt) index exists precisely so this is not a Seq Scan at scale.
            Assert.DoesNotContain("Seq Scan", plan);

            // Stricter, and the point of NFR-004: no Sort node either. A sort would mean the
            // database materialises and orders the whole due set before the LIMIT takes 500 of it,
            // so tick cost would scale with the backlog instead of with the batch. This is what
            // regresses the moment anyone folds the two halves back into one COALESCE ordering.
            Assert.DoesNotContain("Sort", plan);
        }
    }

    [Fact]
    public async Task Every_endpoint_is_reached_within_a_bounded_number_of_ticks()
    {
        if (Skip()) return;
        await using var db = await SeededAsync();

        // The scheduler takes the longest-waiting first, so repeated ticks must drain the backlog
        // rather than revisiting the same monitors — that is what makes starvation impossible.
        const int batchSize = 500;
        var seen = new HashSet<Guid>();
        var now = DateTimeOffset.UtcNow;

        for (var tick = 0; tick < 8; tick++)
        {
            var batch = await DueBatch(db, now, batchSize);
            if (batch.Count == 0) break;

            foreach (var id in batch) seen.Add(id);

            // Mark them probed, as a real tick would.
            await db.Database.ExecuteSqlRawAsync(
                """UPDATE "MonitorEndpoints" SET "LastProbeAt" = now() WHERE "Id" = ANY({0})""",
                batch.ToArray());
        }

        output.WriteLine($"{seen.Count} distinct endpoints probed across 8 ticks");
        // Eight ticks of 500 is four thousand distinct monitors: no repeats, no starvation.
        Assert.Equal(8 * batchSize, seen.Count);
    }

    [Fact]
    public async Task A_never_probed_monitor_is_taken_before_the_long_standing_backlog()
    {
        if (Skip()) return;
        await using var db = await SeededAsync();

        // The two-query split exists for the plan, but it must not change what the scheduler
        // means: a monitor added today cannot queue behind ten thousand older ones. Postgres
        // stores nulls last in a btree, so a single ORDER BY would put it exactly there.
        var newcomer = Guid.NewGuid();
        await db.Database.ExecuteSqlRawAsync($"""
            INSERT INTO "MonitorEndpoints"
                ("Id", "TenantId", "Host", "Port", "Enabled", "ExternalProbeEnabled",
                 "LastProbeStatus", "InternalProbeStatus", "Protocol", "HealthCheckStatus",
                 "CreatedAt", "UpdatedAt", "LastProbeAt", "RetryCount")
            VALUES ('{newcomer}', '{Tenant.DefaultTenantId}', 'newcomer.example.com', 443,
                    true, true, 0, 0, 'tls', 'NotConfigured', now(), now(), NULL, 1);
            """);

        var batch = await DueBatch(db, DateTimeOffset.UtcNow, 500);

        Assert.Equal(newcomer, batch[0]);
    }

    /// <summary>
    /// The never-probed half of a tick's work, as ProbeSchedulerService issues it.
    /// </summary>
    private static IQueryable<Guid> NeverProbedQuery(RemoteSslDbContext db, int batchSize) =>
        db.MonitorEndpoints
            .Where(m => m.Enabled && m.LastProbeAt == null)
            .Take(batchSize)
            .Select(m => m.Id);

    /// <summary>
    /// The longest-waiting half. Kept next to the scheduler's shape so the timing test and the
    /// plan test can never drift apart from each other or from the code they are about.
    /// </summary>
    private static IQueryable<Guid> OverdueQuery(RemoteSslDbContext db, DateTimeOffset now, int batchSize) =>
        db.MonitorEndpoints
            .Where(m => m.Enabled && m.LastProbeAt != null && m.LastProbeAt < now.AddMinutes(-60))
            .OrderBy(m => m.LastProbeAt)
            .Take(batchSize)
            .Select(m => m.Id);

    private static async Task<List<Guid>> DueBatch(RemoteSslDbContext db, DateTimeOffset now, int batchSize)
    {
        var due = await NeverProbedQuery(db, batchSize).ToListAsync();
        if (due.Count < batchSize)
            due.AddRange(await OverdueQuery(db, now, batchSize - due.Count).ToListAsync());
        return due;
    }

    private static async Task<string> ExplainAsync(RemoteSslDbContext db, string sql)
    {
        await using var connection = new Npgsql.NpgsqlConnection(ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "EXPLAIN " + sql;
        await using var reader = await command.ExecuteReaderAsync();

        var lines = new List<string>();
        while (await reader.ReadAsync()) lines.Add(reader.GetString(0));
        return string.Join('\n', lines);
    }
}
