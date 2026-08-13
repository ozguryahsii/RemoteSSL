using Microsoft.Extensions.Configuration;
using Npgsql;

namespace RemoteSSL.Infrastructure.Scheduling;

/// <summary>
/// Postgres advisory-lock leader election (design doc §34.1): schedulers take a
/// per-tick session lock so only one control-plane node runs a given scheduled task
/// even when the API is scaled horizontally.
/// </summary>
public class PostgresLeaderLock(IConfiguration config)
{
    public async Task<bool> RunAsLeaderAsync(long lockKey, Func<Task> work, CancellationToken ct)
    {
        await using var conn = new NpgsqlConnection(config.GetConnectionString("Database"));
        await conn.OpenAsync(ct);
        await using (var cmd = new NpgsqlCommand("SELECT pg_try_advisory_lock(@k)", conn))
        {
            cmd.Parameters.AddWithValue("k", lockKey);
            if (await cmd.ExecuteScalarAsync(ct) is not true) return false;
        }
        try
        {
            await work();
            return true;
        }
        finally
        {
            await using var unlock = new NpgsqlCommand("SELECT pg_advisory_unlock(@k)", conn);
            unlock.Parameters.AddWithValue("k", lockKey);
            await unlock.ExecuteScalarAsync(CancellationToken.None);
        }
    }
}
