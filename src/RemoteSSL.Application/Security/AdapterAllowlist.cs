using System.Text.Json;

namespace RemoteSSL.Application.Security;

/// <summary>Why an adapter was refused, phrased so an operator can fix it.</summary>
public sealed record AdapterVerdict(bool Allowed, string? Reason)
{
    public static readonly AdapterVerdict Ok = new(true, null);
}

/// <summary>
/// Supply-chain control over adapters (design doc §30.2, ADR-006). RemoteSSL ships its
/// adapters in the runner binary rather than as downloadable plugins, so the controls that
/// apply here are an allowlist of adapter types and version pinning of what a runner reports.
/// Package signing belongs to a plugin distribution model that does not exist yet, and
/// pretending otherwise would be security theatre.
/// </summary>
public static class AdapterAllowlist
{
    /// <summary>
    /// An empty allowlist means "no restriction" — an install that has not configured one
    /// keeps working. A configured allowlist refuses everything it does not name.
    /// </summary>
    public static AdapterVerdict Check(
        IReadOnlyList<string> allowedAdapters,
        IReadOnlyDictionary<string, string> pinnedVersions,
        string adapter,
        string? runnerAdapterVersionsJson)
    {
        if (allowedAdapters.Count > 0
            && !allowedAdapters.Any(a => string.Equals(a, adapter, StringComparison.OrdinalIgnoreCase)))
        {
            return new AdapterVerdict(false,
                $"Adapter '{adapter}' is not on the allowlist ({string.Join(", ", allowedAdapters)}).");
        }

        if (!pinnedVersions.TryGetValue(adapter, out var required)) return AdapterVerdict.Ok;

        var reported = ParseVersions(runnerAdapterVersionsJson);
        if (!reported.TryGetValue(adapter, out var actual))
        {
            return new AdapterVerdict(false,
                $"Adapter '{adapter}' is pinned to {required} but the runner did not report a version for it.");
        }

        return string.Equals(actual, required, StringComparison.OrdinalIgnoreCase)
            ? AdapterVerdict.Ok
            : new AdapterVerdict(false,
                $"Adapter '{adapter}' is pinned to {required}; the runner reports {actual}.");
    }

    public static Dictionary<string, string> ParseVersions(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
