using RemoteSSL.Domain;

namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// Performs a credential-less TLS handshake against host:port (with optional SNI)
/// and captures the presented leaf + intermediate chain without trusting it.
/// </summary>
public interface ITlsProber
{
    /// <param name="timeout">Connect + handshake budget; the prober's default applies when null.</param>
    /// <param name="retries">Extra attempts on a transient failure (§29.2).</param>
    Task<TlsProbeResult> ProbeAsync(string host, int port, string? sni, CancellationToken ct,
        TimeSpan? timeout = null, int retries = 0);
}

/// <summary>
/// Raw outcome of one probe. Certificates are DER-encoded; parsing/correlation is a
/// separate concern so the prober stays a thin network component.
/// </summary>
public sealed record TlsProbeResult(
    ProbeStatus Status,
    string? Error,
    byte[]? LeafDer,
    IReadOnlyList<byte[]> ChainDer,
    string? TlsProtocol,
    bool? HostnameValid,
    bool? ChainValid,
    string? ChainError,
    /// <summary>Negotiated cipher suite, when the platform exposes it (§6.2).</summary>
    string? CipherSuite = null);
