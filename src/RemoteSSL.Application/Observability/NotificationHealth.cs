namespace RemoteSSL.Application.Observability;

/// <summary>
/// Tracks delivery failures per channel so §33's "notification failure raises its own alarm"
/// holds. A webhook that stops working must not fail a deployment — but it must not pass
/// unnoticed either, which is what this makes possible. Singleton, like the audit-pipeline
/// tracker, because a channel outage says nothing about whether the database is reachable.
/// </summary>
public class NotificationHealth
{
    private readonly object gate = new();
    private readonly Queue<Failure> failures = new();

    public sealed record Failure(DateTimeOffset Timestamp, string Channel, string EventType, string Error);

    public void RecordFailure(string channel, string eventType, Exception ex) =>
        RecordFailure(channel, eventType, ex.GetType().Name + ": " + ex.Message);

    public void RecordFailure(string channel, string eventType, string error)
    {
        lock (gate)
        {
            failures.Enqueue(new Failure(DateTimeOffset.UtcNow, channel, eventType, error));
            while (failures.Count > 100) failures.Dequeue();
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

    /// <summary>Failure counts per channel inside the window, for the dashboard alarm panel.</summary>
    public IReadOnlyDictionary<string, int> CountsByChannel(TimeSpan window) =>
        Recent(window).GroupBy(f => f.Channel).ToDictionary(g => g.Key, g => g.Count());
}
