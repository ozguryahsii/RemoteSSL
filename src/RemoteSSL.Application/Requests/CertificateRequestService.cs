using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Requests;

public interface ICaConnectorResolver
{
    Task<ICertificateAuthorityConnector> ResolveAsync(Guid caConnectorId, CancellationToken ct);
}

/// <summary>
/// Certificate request lifecycle (design doc §17-19): validation → CSR → CA submit →
/// poll → issued version in inventory. Central key origin keeps the private key
/// data-protection-encrypted until the version is created, then hands it to the
/// version and clears it from the request.
/// </summary>
public class CertificateRequestService(
    IRemoteSslDbContext db, ISecretProtector protector, InventoryService inventory,
    ICaConnectorResolver connectors, AuditWriter audit)
{
    public async Task<CertificateRequestEntity> CreateAsync(
        string commonName, IReadOnlyList<string> sans, string keyAlgorithm, int keySizeOrCurve,
        string keyOrigin, Guid? caConnectorId, string? profileId, string requestedBy, CancellationToken ct)
    {
        if (keyAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase) && keySizeOrCurve < 2048)
            throw new ArgumentException("RSA key size below policy minimum 2048");

        var normalizedSans = sans.Select(s => s.Trim().ToLowerInvariant())
            .Where(s => s.Length > 0).Distinct().ToList();
        if (!normalizedSans.Contains(commonName.ToLowerInvariant())) normalizedSans.Insert(0, commonName.ToLowerInvariant());

        var req = new CertificateRequestEntity
        {
            Id = Guid.NewGuid(),
            CommonName = commonName,
            SansJson = JsonSerializer.Serialize(normalizedSans),
            KeyAlgorithm = keyAlgorithm.ToUpperInvariant(),
            KeySizeOrCurve = keySizeOrCurve,
            KeyOrigin = keyOrigin,
            CaConnectorId = caConnectorId,
            ProfileId = profileId,
            State = CertificateRequestState.Validated,
            RequestedBy = requestedBy,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        if (keyOrigin == "central")
        {
            var artifacts = CertificateFactory.GenerateCsr(commonName, normalizedSans, req.KeyAlgorithm, keySizeOrCurve);
            req.CsrPem = artifacts.CsrPem;
            req.EncryptedPrivateKeyPem = protector.Protect(artifacts.PrivateKeyPem);
            req.State = CertificateRequestState.CsrGenerated;
        }

        db.CertificateRequests.Add(req);
        audit.Append($"user:{requestedBy}", "certificate.request", "certificate_request", req.Id.ToString(),
            req.State.ToString(), new { commonName, sans = normalizedSans, keyAlgorithm, keySizeOrCurve, keyOrigin });
        await db.SaveChangesAsync(ct);

        if (caConnectorId is not null && req.CsrPem is not null)
            await SubmitAsync(req, ct);
        return req;
    }

    public async Task SubmitAsync(CertificateRequestEntity req, CancellationToken ct)
    {
        var connector = await connectors.ResolveAsync(req.CaConnectorId!.Value, ct);
        try
        {
            var reference = await connector.SubmitRequestAsync(req.CsrPem!, req.ProfileId ?? "default",
                new Dictionary<string, string>(), ct);
            req.ProviderRequestId = reference.ProviderRequestId;
            req.State = connector.ConnectorType == "manual"
                ? CertificateRequestState.WaitingForCertificate
                : CertificateRequestState.PendingIssuance;
            req.ErrorMessage = null;
        }
        catch (Exception ex)
        {
            req.State = CertificateRequestState.FailedRetryable;
            req.ErrorMessage = ex.Message;
        }
        req.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append("service:lifecycle", "certificate.request.submit", "certificate_request",
            req.Id.ToString(), req.State.ToString());
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Scheduler hook: polls pending CA requests and lands issued certificates in the inventory.</summary>
    public async Task PollPendingAsync(CancellationToken ct)
    {
        var pending = await db.CertificateRequests
            .Where(r => r.State == CertificateRequestState.PendingIssuance
                        || r.State == CertificateRequestState.SubmittedToCa)
            .Where(r => r.CaConnectorId != null && r.ProviderRequestId != null)
            .Take(20).ToListAsync(ct);

        foreach (var req in pending)
        {
            try
            {
                var connector = await connectors.ResolveAsync(req.CaConnectorId!.Value, ct);
                var reference = new CaRequestRef(connector.ConnectorType, req.ProviderRequestId!);
                var status = await connector.GetRequestStatusAsync(reference, ct);
                if (status.State == CaRequestState.Issued)
                {
                    var issued = await connector.DownloadCertificateAsync(reference, ct);
                    await BindIssuedAsync(req, issued.LeafPem, issued.ChainPem, ct);
                }
                else if (status.State is CaRequestState.Rejected or CaRequestState.Failed)
                {
                    req.State = CertificateRequestState.FailedBlocked;
                    req.ErrorMessage = status.Detail;
                    req.UpdatedAt = DateTimeOffset.UtcNow;
                }
            }
            catch (Exception ex)
            {
                req.ErrorMessage = ex.Message;
                req.UpdatedAt = DateTimeOffset.UtcNow;
            }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Manual CA path: operator uploads the signed leaf + chain.</summary>
    public async Task UploadIssuedAsync(Guid requestId, string certPem, string? chainPem, CancellationToken ct)
    {
        var req = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct)
                  ?? throw new KeyNotFoundException("Request not found");
        if (req.State is not (CertificateRequestState.WaitingForCertificate or CertificateRequestState.PendingIssuance
            or CertificateRequestState.CsrGenerated))
            throw new InvalidOperationException($"Request is {req.State}; cannot accept a certificate upload");
        await BindIssuedAsync(req, certPem, chainPem, ct);
        await db.SaveChangesAsync(ct);
    }

    private async Task BindIssuedAsync(CertificateRequestEntity req, string certPem, string? chainPem, CancellationToken ct)
    {
        var version = await inventory.AddVersionAsync(certPem, chainPem, req.EncryptedPrivateKeyPem,
            CertificateVersionStatus.Issued, ct);
        req.IssuedVersionId = version.Id;
        req.CertificateId = version.CertificateId;
        req.EncryptedPrivateKeyPem = null; // key now lives on the version
        req.State = CertificateRequestState.Issued;
        req.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append("service:lifecycle", "certificate.issued", "certificate_request", req.Id.ToString(),
            "ISSUED", new { req.CommonName, versionId = version.Id });
    }
}
