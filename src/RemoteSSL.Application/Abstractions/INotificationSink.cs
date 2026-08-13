namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// Event-driven notification fan-out (design doc §33). Implementations must be
/// fire-and-forget: a notification failure never changes the outcome of the
/// operation that raised it.
/// </summary>
public interface INotificationSink
{
    void Notify(string eventType, object payload);
}
