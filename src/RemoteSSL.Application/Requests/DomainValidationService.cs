using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Requests;

/// <summary>
/// A connector that can walk an order's domain validation itself (design doc §18.1). ACME is the
/// case that needs it: challenges only exist inside an order, so they cannot be arranged through
/// <see cref="ICertificateAuthorityConnector.RequestDomainValidationAsync"/> beforehand.
/// </summary>
public interface IOrderValidationConnector
{
    Task<IReadOnlyList<DomainValidationChallenge>> GetOrderChallengesAsync(CaRequestRef request, CancellationToken ct);
    Task<bool> AnswerChallengeAsync(string challengeReference, CancellationToken ct);
    Task FinalizeAsync(CaRequestRef request, string csrPem, CancellationToken ct);
}

/// <summary>
/// Domain validation as an operator sees it (design doc §18.1): what has to be published, where,
/// and whether the CA has accepted it yet. The rows are refreshed from the CA rather than assumed,
/// so a challenge that the CA already satisfied elsewhere is not asked for twice.
/// </summary>
public class DomainValidationService(
    IRemoteSslDbContext db, ICaConnectorResolver connectors, AuditWriter audit)
{
    /// <summary>
    /// Pulls the outstanding challenges for a request from its CA and records them. Existing rows
    /// are updated rather than duplicated, so re-running this is safe and idempotent.
    /// </summary>
    public async Task<IReadOnlyList<DomainValidation>> RefreshAsync(Guid requestId, CancellationToken ct)
    {
        var request = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct)
                      ?? throw new KeyNotFoundException("Certificate request not found");
        if (request.CaConnectorId is null || request.ProviderRequestId is null)
            return await ExistingAsync(requestId, ct);

        var connector = await connectors.ResolveAsync(request.CaConnectorId.Value, ct);
        if (connector is not IOrderValidationConnector orderConnector)
            return await ExistingAsync(requestId, ct);

        var challenges = await orderConnector.GetOrderChallengesAsync(
            new CaRequestRef(connector.ConnectorType, request.ProviderRequestId), ct);

        var existing = await db.DomainValidations
            .Where(v => v.CertificateRequestId == requestId)
            .ToListAsync(ct);

        foreach (var challenge in challenges)
        {
            var row = existing.FirstOrDefault(v => v.Domain == challenge.Domain && v.Method == challenge.Method);
            if (row is null)
            {
                row = new DomainValidation
                {
                    Id = Guid.NewGuid(),
                    CertificateRequestId = requestId,
                    CaConnectorId = request.CaConnectorId.Value,
                    Domain = challenge.Domain,
                    Method = challenge.Method,
                    CreatedAt = DateTimeOffset.UtcNow
                };
                db.DomainValidations.Add(row);
                existing.Add(row);
            }
            row.ChallengeReference = challenge.ChallengeToken;
            row.ExpectedDnsRecord = challenge.ExpectedDnsRecord;
            row.ExpectedHttpResponse = challenge.ExpectedHttpPath;
            row.ExpiresAt = challenge.ExpiresAt;
            if (row.State is DomainValidationState.Valid or DomainValidationState.Failed)
                row.State = DomainValidationState.Pending; // the CA still lists it, so it is not done
        }

        // A challenge the CA no longer lists has been satisfied; saying so is more useful than
        // leaving a row that will never change again.
        foreach (var stale in existing.Where(v =>
                     v.State != DomainValidationState.Valid
                     && !challenges.Any(c => c.Domain == v.Domain && c.Method == v.Method)))
        {
            stale.State = DomainValidationState.Valid;
            stale.CompletedAt = DateTimeOffset.UtcNow;
            stale.Detail = "the CA no longer lists this authorization as outstanding";
        }

        await db.SaveChangesAsync(ct);
        return existing;
    }

    /// <summary>
    /// Tells the CA the proof is published and to go and check. The answer is not the result —
    /// validation is asynchronous, and the state moves to Valid only when the CA says so.
    /// </summary>
    public async Task<DomainValidation> SubmitAsync(Guid validationId, string actor, CancellationToken ct)
    {
        var validation = await db.DomainValidations.FirstOrDefaultAsync(v => v.Id == validationId, ct)
                         ?? throw new KeyNotFoundException("Domain validation not found");

        var connector = await connectors.ResolveAsync(validation.CaConnectorId, ct);
        if (connector is not IOrderValidationConnector orderConnector)
            throw new InvalidOperationException(
                $"Connector '{connector.ConnectorType}' handles domain validation outside RemoteSSL.");

        var accepted = await orderConnector.AnswerChallengeAsync(validation.ChallengeReference, ct);
        validation.State = accepted ? DomainValidationState.Submitted : DomainValidationState.Failed;
        validation.SubmittedAt = DateTimeOffset.UtcNow;
        validation.Detail = accepted
            ? "the CA has been asked to verify the published proof"
            : "the CA refused the challenge answer";

        audit.Append(actor, "domain-validation.submit", "domain_validation", validationId.ToString(),
            accepted ? "OK" : "FAILED", new { validation.Domain, validation.Method });
        await db.SaveChangesAsync(ct);
        return validation;
    }

    private async Task<IReadOnlyList<DomainValidation>> ExistingAsync(Guid requestId, CancellationToken ct) =>
        await db.DomainValidations.Where(v => v.CertificateRequestId == requestId).ToListAsync(ct);
}
