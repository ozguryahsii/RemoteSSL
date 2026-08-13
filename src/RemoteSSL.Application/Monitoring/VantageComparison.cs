using RemoteSSL.Domain;

namespace RemoteSSL.Application.Monitoring;

/// <summary>Which side of the network a probe was executed from.</summary>
public enum ProbeVantage
{
    /// <summary>Control plane — what the outside world (public/corporate DNS) sees.</summary>
    External = 0,
    /// <summary>Runner next to the application — what the service itself serves internally.</summary>
    Internal
}

public enum VantageVerdict
{
    /// <summary>No internal vantage configured — nothing to compare.</summary>
    NotConfigured = 0,
    /// <summary>Both vantages see the same certificate.</summary>
    Match,
    /// <summary>Both reachable but serving different certificates — a layer was missed during renewal.</summary>
    Mismatch,
    /// <summary>Only the external vantage answered.</summary>
    ExternalOnly,
    /// <summary>Only the internal vantage answered (typical for internal-DNS-only services).</summary>
    InternalOnly,
    /// <summary>Neither vantage could complete a handshake.</summary>
    BothUnreachable
}

/// <summary>
/// Compares what the outside sees with what the application server itself serves.
/// A mismatch is the fingerprint of a renewal applied to one layer only (e.g. the
/// load balancer updated, the backend forgotten).
/// </summary>
public static class VantageComparison
{
    public static (VantageVerdict Verdict, string Detail) Compare(
        bool internalConfigured,
        ProbeStatus externalStatus, string? externalThumbprint, DateTimeOffset? externalNotAfter,
        ProbeStatus internalStatus, string? internalThumbprint, DateTimeOffset? internalNotAfter)
    {
        var extOk = externalStatus == ProbeStatus.Success && externalThumbprint is not null;
        var intOk = internalStatus == ProbeStatus.Success && internalThumbprint is not null;

        if (!internalConfigured)
            return (VantageVerdict.NotConfigured, "No internal vantage assigned — add a runner to compare inside vs outside.");

        if (extOk && intOk)
        {
            if (string.Equals(externalThumbprint, internalThumbprint, StringComparison.OrdinalIgnoreCase))
                return (VantageVerdict.Match, "Outside and inside serve the same certificate.");

            var newer = externalNotAfter > internalNotAfter ? "external" : "internal";
            var stale = newer == "external" ? "internal (application server)" : "external (published endpoint)";
            return (VantageVerdict.Mismatch,
                $"Different certificates: external expires {externalNotAfter:yyyy-MM-dd}, internal expires {internalNotAfter:yyyy-MM-dd}. " +
                $"The {stale} side looks stale — its certificate was likely not replaced during the last renewal.");
        }

        if (extOk)
            return (VantageVerdict.ExternalOnly, $"Internal probe failed: {internalStatus}. The application server did not answer the runner.");
        if (intOk)
            return (VantageVerdict.InternalOnly, $"External probe failed: {externalStatus}. Not published (or not resolvable) outside.");

        return (VantageVerdict.BothUnreachable, $"External: {externalStatus}; internal: {internalStatus}.");
    }
}
