using System.Text.Json;

namespace RemoteSSL.Application.Policies;

/// <summary>
/// Maintenance window evaluation (FR-014, §20.1, §23.2). Shared by the renewal engine and
/// the deployment orchestrator so automatic and manual deployments obey the same window.
/// </summary>
public static class MaintenanceWindow
{
    /// <summary>Window JSON: {"days":["SUN","MON"],"start":"01:00","end":"04:00"} evaluated in UTC.</summary>
    public static bool IsOpen(string windowJson, DateTimeOffset nowUtc)
    {
        try
        {
            using var doc = JsonDocument.Parse(windowJson);
            var root = doc.RootElement;
            if (root.TryGetProperty("days", out var days))
            {
                var today = nowUtc.DayOfWeek.ToString()[..3].ToUpperInvariant();
                if (!days.EnumerateArray().Any(d => string.Equals(d.GetString(), today, StringComparison.OrdinalIgnoreCase)))
                    return false;
            }
            var start = TimeSpan.Parse(root.GetProperty("start").GetString()!);
            var end = TimeSpan.Parse(root.GetProperty("end").GetString()!);
            var t = nowUtc.TimeOfDay;
            return start <= end ? t >= start && t <= end : t >= start || t <= end;
        }
        catch
        {
            return true; // malformed window must not block forever; audit trail shows execution time
        }
    }
}
