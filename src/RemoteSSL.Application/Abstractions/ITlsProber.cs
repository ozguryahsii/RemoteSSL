using RemoteSSL.Domain;

namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// Performs a credential-less TLS handshake against host:port (with optional SNI)
/// and captures the presented leaf + intermediate chain without trusting it.
/// </summary>
public interface ITlsProber
{
    Task<TlsProbeResult> ProbeAsync(string host, int port, string? sni, CancellationToken ct);
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
    string? ChainError);
