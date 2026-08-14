using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Application.Observability;
using RemoteSSL.Application.Policies;
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
    ICaConnectorResolver connectors, AuditWriter audit, GovernanceService governance)
{
    /// <summary>Non-blocking findings from the last create call, surfaced to the wizard (§17.2).</summary>
    public IReadOnlyList<PolicyFinding> LastWarnings { get; private set; } = [];

    public async Task<CertificateRequestEntity> CreateAsync(
        string commonName, IReadOnlyList<string> sans, string keyAlgorithm, int keySizeOrCurve,
        string keyOrigin, Guid? caConnectorId, string? profileId, string requestedBy, CancellationToken ct,
        Guid? targetId = null, string? targetKeyPath = null, CertificateFactory.SubjectOptions? subject = null,
        Guid? certificateId = null, string? environment = null, string? ownerId = null,
        int? requestedValidityDays = null)
    {
        // One trace id follows this request through CA submission, issuance and deployment (§32.2).
        using var trace = TraceContext.Begin("certificate.request");
        trace.SetTag("remotessl.common_name", commonName);

        var normalizedSans = PolicyEvaluator.NormalizeNames(commonName, sans).ToList();

        // §17.2 / §39: every rule of the effective certificate policy, evaluated up front.
        var policy = await governance.ResolveAsync(certificateId, ct);
        var overlaps = policy.WarnOnOverlap
            ? await governance.FindOverlappingAsync(normalizedSans, certificateId, ct)
            : [];
        var findings = PolicyEvaluator.ValidateRequest(policy, new RequestFacts(
            commonName, normalizedSans, keyAlgorithm, keySizeOrCurve, ownerId, requestedValidityDays, overlaps));
        if (findings.Any(f => f.Blocking)) throw new PolicyViolationException(findings);
        LastWarnings = findings;

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
            Environment = environment,
            OwnerId = ownerId,
            CertificateId = certificateId,
            CorrelationId = trace.CorrelationId,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        // §19.1/§23.2: environments listed in the policy stop here until a checker approves.
        // No key or CSR is produced before the decision.
        if (PolicyEvaluator.RequiresApproval(policy, environment))
        {
            req.State = CertificateRequestState.PendingApproval;
            db.CertificateRequests.Add(req);
            db.ApprovalRequests.Add(new ApprovalRequest
            {
                Id = Guid.NewGuid(),
                ObjectType = "certificate_request",
                CertificateRequestId = req.Id,
                RequestedBy = requestedBy,
                CreatedAt = DateTimeOffset.UtcNow
            });
            audit.Append($"user:{requestedBy}", "certificate.request", "certificate_request", req.Id.ToString(),
                req.State.ToString(),
                new { commonName, sans = normalizedSans, keyAlgorithm, keySizeOrCurve, keyOrigin, environment },
                trace.CorrelationId);
            await db.SaveChangesAsync(ct);
            return req;
        }

        await BuildCsrAsync(req, keyOrigin, commonName, normalizedSans, keySizeOrCurve, subject,
            targetId, targetKeyPath, trace.CorrelationId, ct);

        db.CertificateRequests.Add(req);
        audit.Append($"user:{requestedBy}", "certificate.request", "certificate_request", req.Id.ToString(),
            req.State.ToString(),
            new { commonName, sans = normalizedSans, keyAlgorithm, keySizeOrCurve, keyOrigin, environment },
            trace.CorrelationId);
        await db.SaveChangesAsync(ct);

        if (caConnectorId is not null && req.CsrPem is not null)
            await SubmitAsync(req, ct);
        return req;
    }

    /// <summary>
    /// Approves or rejects a certificate request (§19.1 PENDING_APPROVAL). On approval the
    /// key/CSR work runs and the request continues to the CA; on rejection it ends REJECTED.
    /// </summary>
    public async Task ApproveAsync(Guid requestId, string approver, bool approve, string? reason,
        bool approverIsBreakGlass, CancellationToken ct)
    {
        var req = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct)
                  ?? throw new KeyNotFoundException("Request not found");
        if (req.State != CertificateRequestState.PendingApproval)
            throw new InvalidOperationException($"Request is {req.State}, not awaiting approval");

        using var trace = TraceContext.Begin("certificate.request.approve", NonEmpty(req.CorrelationId));

        var policy = await governance.ResolveAsync(req.CertificateId, ct);
        var decision = GovernanceService.CheckApprover(policy, req.RequestedBy, approver, approverIsBreakGlass);
        if (decision == ApproverDecision.SelfApprovalRefused)
            throw new InvalidOperationException("Requester cannot approve their own certificate request");

        var approval = await db.ApprovalRequests.FirstOrDefaultAsync(a => a.CertificateRequestId == requestId, ct);
        if (approval is not null)
        {
            approval.Status = approve ? "Approved" : "Rejected";
            approval.DecidedBy = approver;
            approval.Reason = reason;
            approval.BreakGlass = decision == ApproverDecision.BreakGlass;
            approval.DecidedAt = DateTimeOffset.UtcNow;
        }

        if (!approve)
        {
            req.State = CertificateRequestState.Rejected;
            req.UpdatedAt = DateTimeOffset.UtcNow;
            audit.Append($"user:{approver}", "certificate.request.reject", "certificate_request",
                req.Id.ToString(), "REJECTED", new { reason }, trace.CorrelationId);
            await db.SaveChangesAsync(ct);
            return;
        }

        var sans = JsonSerializer.Deserialize<List<string>>(req.SansJson) ?? [req.CommonName];
        await BuildCsrAsync(req, req.KeyOrigin, req.CommonName, sans, req.KeySizeOrCurve, null,
            req.TargetId, req.TargetKeyPath, trace.CorrelationId, ct);
        req.UpdatedAt = DateTimeOffset.UtcNow;

        audit.Append($"user:{approver}", "certificate.request.approve", "certificate_request",
            req.Id.ToString(), decision == ApproverDecision.BreakGlass ? "APPROVED_BREAK_GLASS" : "APPROVED",
            new { reason, breakGlass = decision == ApproverDecision.BreakGlass }, trace.CorrelationId);
        await db.SaveChangesAsync(ct);

        if (req.CaConnectorId is not null && req.CsrPem is not null)
            await SubmitAsync(req, ct);
    }

    /// <summary>Produces the key/CSR for the request's key origin (central or on-target).</summary>
    private async Task BuildCsrAsync(
        CertificateRequestEntity req, string keyOrigin, string commonName, IReadOnlyList<string> normalizedSans,
        int keySizeOrCurve, CertificateFactory.SubjectOptions? subject, Guid? targetId, string? targetKeyPath,
        string correlationId, CancellationToken ct)
    {
        if (keyOrigin == "central")
        {
            var artifacts = CertificateFactory.GenerateCsr(commonName, normalizedSans, req.KeyAlgorithm, keySizeOrCurve, subject);
            req.CsrPem = artifacts.CsrPem;
            req.EncryptedPrivateKeyPem = protector.Protect(artifacts.PrivateKeyPem);
            req.State = CertificateRequestState.CsrGenerated;
        }
        else if (keyOrigin == "target")
        {
            // Preferred model (design doc §16.1): key is generated on the target and never leaves it.
            var target = await db.Targets.AsNoTracking().FirstOrDefaultAsync(t => t.Id == targetId, ct)
                         ?? throw new ArgumentException("On-target key origin requires a valid targetId");
            if (string.IsNullOrWhiteSpace(targetKeyPath))
                throw new ArgumentException("On-target key origin requires targetKeyPath");
            req.TargetId = target.Id;
            req.TargetKeyPath = targetKeyPath;

            using var conn = JsonDocument.Parse(target.ConnectionConfigJson);
            string Host() => conn.RootElement.TryGetProperty("host", out var h) ? h.GetString() ?? target.Name : target.Name;
            int Port() => conn.RootElement.TryGetProperty("port", out var p) && p.TryGetInt32(out var pi) ? pi : 22;

            db.RunnerJobs.Add(new RunnerJob
            {
                Id = Guid.NewGuid(),
                RunnerId = target.RunnerId,
                JobType = "generate-csr",
                PayloadJson = JsonSerializer.Serialize(new
                {
                    kind = "linux",
                    requestId = req.Id,
                    connection = new { host = Host(), port = Port(), useSudo = false },
                    credentialRefId = target.CredentialRefId,
                    keyPath = targetKeyPath,
                    commonName,
                    sans = normalizedSans,
                    keyAlgorithm = req.KeyAlgorithm,
                    keySizeOrCurve
                }),
                CorrelationId = correlationId,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }
    }

    public async Task SubmitAsync(CertificateRequestEntity req, CancellationToken ct)
    {
        using var trace = TraceContext.Begin("certificate.request.submit", NonEmpty(req.CorrelationId));
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
            req.Id.ToString(), req.State.ToString(), null, trace.CorrelationId);
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
            using var trace = TraceContext.Begin("certificate.request.poll", NonEmpty(req.CorrelationId));
            try
            {
                var connector = await connectors.ResolveAsync(req.CaConnectorId!.Value, ct);
                var reference = new CaRequestRef(connector.ConnectorType, req.ProviderRequestId!);
                var status = await connector.GetRequestStatusAsync(reference, ct);

                // ACME makes finalize an explicit step once every authorization is valid; without
                // it the order sits at "ready" forever and never produces a certificate (§18.3).
                if (status.State == CaRequestState.Pending
                    && connector is IOrderValidationConnector orderConnector
                    && req.CsrPem is not null)
                {
                    await orderConnector.FinalizeAsync(reference, req.CsrPem, ct);
                    status = await connector.GetRequestStatusAsync(reference, ct);
                }

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

    /// <summary>
    /// Polls one request now (ADR-009). A CA webhook says "something changed about this request";
    /// what changed still has to be read from the CA, because a callback is a hint, never a source
    /// of truth about issuance. Polling remains the fallback for CAs that send nothing.
    /// </summary>
    public async Task<CertificateRequestState> PollOneAsync(Guid requestId, CancellationToken ct)
    {
        var req = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct)
                  ?? throw new KeyNotFoundException("Request not found");
        if (req.CaConnectorId is null || req.ProviderRequestId is null) return req.State;
        if (req.State is CertificateRequestState.Issued or CertificateRequestState.FailedBlocked) return req.State;

        using var trace = TraceContext.Begin("certificate.request.webhook-poll", NonEmpty(req.CorrelationId));
        var connector = await connectors.ResolveAsync(req.CaConnectorId.Value, ct);
        var reference = new CaRequestRef(connector.ConnectorType, req.ProviderRequestId);
        var status = await connector.GetRequestStatusAsync(reference, ct);

        if (status.State == CaRequestState.Pending
            && connector is IOrderValidationConnector orderConnector && req.CsrPem is not null)
        {
            await orderConnector.FinalizeAsync(reference, req.CsrPem, ct);
            status = await connector.GetRequestStatusAsync(reference, ct);
        }

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

        await db.SaveChangesAsync(ct);
        return req.State;
    }

    /// <summary>Runner completed an on-target CSR generation job: attach the CSR and continue the lifecycle.</summary>
    public async Task AttachTargetCsrAsync(Guid requestId, string csrPem, CancellationToken ct)
    {
        var req = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct)
                  ?? throw new KeyNotFoundException("Request not found");
        req.CsrPem = csrPem;
        req.State = CertificateRequestState.CsrGenerated;
        req.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Append("service:lifecycle", "certificate.request.csr-on-target", "certificate_request",
            req.Id.ToString(), "CSR_GENERATED", null, NonEmpty(req.CorrelationId));
        await db.SaveChangesAsync(ct);
        if (req.CaConnectorId is not null) await SubmitAsync(req, ct);
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

    /// <summary>Requests created before trace propagation existed carry no id; those start a fresh one.</summary>
    private static string? NonEmpty(string? correlationId) =>
        string.IsNullOrWhiteSpace(correlationId) ? null : correlationId;

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
            "ISSUED", new { req.CommonName, versionId = version.Id }, NonEmpty(req.CorrelationId));
    }
}
