namespace RemoteSSL.Application.Observability;

/// <summary>
/// Tracks failures of the audit write path so §32.3's "audit pipeline failure" alert
/// can fire. Audit rows are the compliance record (§25): if they stop being written the
/// operators must be told, even though the failure is invisible to the operation itself.
/// Registered as a singleton — the failures it records are exactly the ones the database
/// could not persist, so they cannot be stored in the database.
/// </summary>
public class AuditPipelineHealth
{
    private readonly object gate = new();
    private readonly Queue<Failure> failures = new();

    public sealed record Failure(DateTimeOffset Timestamp, string Action, string Error);

    public void RecordFailure(string action, Exception ex)
    {
        lock (gate)
        {
            failures.Enqueue(new Failure(DateTimeOffset.UtcNow, action, ex.GetType().Name + ": " + ex.Message));
            while (failures.Count > 50) failures.Dequeue();
        }
    }

    /// <summary>Failures inside the window, newest first.</summary>
    public IReadOnlyList<Failure> Recent(TimeSpan window)
    {
        var cutoff = DateTimeOffset.UtcNow - window;
        lock (gate)
        {
            return failures.Where(f => f.Timestamp >= cutoff).OrderByDescending(f => f.Timestamp).ToList();
        }
    }
}
