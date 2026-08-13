using RemoteSSL.Application.Observability;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Infrastructure.Ca;

/// <summary>
/// Times every CA call for the §32.1 <c>ca_request_latency</c> metric. Provider-agnostic
/// by construction: it decorates the interface, so a new connector is measured without
/// touching its code, and it never alters the result or the exception it passes through.
/// </summary>
public class MeasuredCaConnector(ICertificateAuthorityConnector inner, MetricsRecorder metrics)
    : ICertificateAuthorityConnector
{
    public string ConnectorType => inner.ConnectorType;

    private Task<T> Measure<T>(string operation, Func<Task<T>> call, CancellationToken ct) =>
        metrics.TimeAsync(MetricsRecorder.CaRequestLatency, $"{inner.ConnectorType}.{operation}", call, ct: ct);

    private async Task Measure(string operation, Func<Task> call, CancellationToken ct) =>
        await Measure(operation, async () => { await call(); return true; }, ct);

    public Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct) =>
        Measure("validate-connection", () => inner.ValidateConnectionAsync(ct), ct);

    public Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct) =>
        Measure("list-profiles", () => inner.ListProfilesAsync(ct), ct);

    public Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId,
        IReadOnlyDictionary<string, string> metadata, CancellationToken ct) =>
        Measure("submit-request", () => inner.SubmitRequestAsync(csrPem, profileId, metadata, ct), ct);

    public Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct) =>
        Measure("get-status", () => inner.GetRequestStatusAsync(request, ct), ct);

    public Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct) =>
        Measure("download-certificate", () => inner.DownloadCertificateAsync(request, ct), ct);

    public Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId, CancellationToken ct) =>
        Measure("renew", () => inner.RenewAsync(certificateSerial, csrPem, profileId, ct), ct);

    public Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct) =>
        Measure("revoke", () => inner.RevokeAsync(certificateSerial, reason, ct), ct);

    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method, CancellationToken ct) =>
        Measure("request-domain-validation", () => inner.RequestDomainValidationAsync(domain, method, ct), ct);
}
