using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Infrastructure.Tls;

/// <summary>
/// Credential-less TLS probe: TCP connect + TLS handshake with SNI, capturing the
/// presented leaf and intermediates regardless of trust. Validation results are
/// recorded, never enforced — an invalid chain is an observation, not a failure.
/// </summary>
public class TlsProber : ITlsProber
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    public async Task<TlsProbeResult> ProbeAsync(string host, int port, string? sni, CancellationToken ct,
        TimeSpan? timeout = null, int retries = 0)
    {
        // Retries only help transient faults; a DNS or handshake result is an answer, not a
        // hiccup, so those are returned on the first attempt (§29.2).
        TlsProbeResult result;
        var attempt = 0;
        while (true)
        {
            result = await ProbeOnceAsync(host, port, sni, timeout ?? ConnectTimeout, ct);
            var transient = result.Status is ProbeStatus.Timeout or ProbeStatus.ConnectionFailed;
            if (!transient || attempt++ >= retries || ct.IsCancellationRequested) return result;
            await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt), ct);
        }
    }

    private static async Task<TlsProbeResult> ProbeOnceAsync(
        string host, int port, string? sni, TimeSpan timeout, CancellationToken ct)
    {
        byte[]? leafDer = null;
        var chainDer = new List<byte[]>();
        bool? hostnameValid = null;
        bool? chainValid = null;
        string? chainError = null;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);

            using var tcp = new TcpClient();
            try
            {
                await tcp.ConnectAsync(host, port, timeoutCts.Token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
            {
                return Fail(ProbeStatus.DnsResolutionFailed, ex.Message);
            }
            catch (SocketException ex)
            {
                return Fail(ProbeStatus.ConnectionFailed, ex.Message);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return Fail(ProbeStatus.Timeout, $"TCP connect to {host}:{port} timed out");
            }

            await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
                (_, cert, chain, errors) =>
                {
                    if (cert is not null)
                    {
                        leafDer = cert.GetRawCertData();
                        if (chain is not null)
                        {
                            foreach (var element in chain.ChainElements.Skip(1))
                                chainDer.Add(element.Certificate.RawData);
                        }
                    }

                    hostnameValid = !errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
                    chainValid = !errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors)
                                 && !errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable);
                    if (chainValid == false && chain is not null)
                    {
                        chainError = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Distinct());
                    }

                    return true; // always accept: we observe, we don't enforce
                });

            try
            {
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = string.IsNullOrWhiteSpace(sni) ? host : sni,
                    EnabledSslProtocols = SslProtocols.None // OS default: TLS 1.2/1.3
                }, timeoutCts.Token);
            }
            catch (AuthenticationException ex)
            {
                // Handshake failed, but the validation callback may still have captured the cert.
                if (leafDer is null)
                    return Fail(ProbeStatus.TlsHandshakeFailed, ex.GetBaseException().Message);
                return new TlsProbeResult(ProbeStatus.Success, null, leafDer, chainDer,
                    null, hostnameValid, chainValid, chainError ?? ex.GetBaseException().Message);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return Fail(ProbeStatus.Timeout, $"TLS handshake with {host}:{port} timed out");
            }

            return new TlsProbeResult(ProbeStatus.Success, null, leafDer, chainDer,
                ssl.SslProtocol.ToString(), hostnameValid, chainValid, chainError,
                CipherSuiteName(ssl));
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return Fail(ProbeStatus.ConnectionFailed, ex.GetBaseException().Message);
        }

        TlsProbeResult Fail(ProbeStatus status, string error) =>
            new(status, error, null, [], null, null, null, null);
    }

    /// <summary>
    /// The negotiated cipher suite. NegotiatedCipherSuite is unsupported on some platforms
    /// (it throws PlatformNotSupportedException), so its absence is not an error.
    /// </summary>
    private static string? CipherSuiteName(SslStream ssl)
    {
        try
        {
            return ssl.NegotiatedCipherSuite.ToString();
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }
}
