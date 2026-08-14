using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Requests;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Callback endpoint for CAs that can push status changes (ADR-009).
///
/// The hybrid the ADR asks for works like this: a webhook is a hint that something changed about a
/// request, and the platform then reads the actual state from the CA. Nothing about issuance is
/// ever taken from the callback body — a forged callback can at most cause an extra poll. Polling
/// stays on as the fallback, so a CA that sends nothing, or a callback that never arrives, still
/// ends with the certificate collected.
/// </summary>
[ApiController]
[Route("api/v1/ca/webhook")]
[Microsoft.AspNetCore.Authorization.AllowAnonymous] // authenticated by the shared secret below
public class CaWebhookController(
    IRemoteSslDbContext db, CertificateRequestService requests, AuditWriter audit,
    IConfiguration configuration, ILogger<CaWebhookController> logger) : ControllerBase
{
    /// <summary>
    /// Accepts a callback for one connector. The request must carry the shared secret configured
    /// for that connector, either as an HMAC over the body (X-RemoteSSL-Signature) or as the raw
    /// token (X-RemoteSSL-Token), depending on what the CA can send.
    /// </summary>
    [HttpPost("{connectorId:guid}")]
    public async Task<IActionResult> Receive(Guid connectorId, CancellationToken ct)
    {
        var secret = configuration[$"Ca:Webhook:{connectorId}:Secret"] ?? configuration["Ca:Webhook:Secret"];
        if (string.IsNullOrWhiteSpace(secret))
        {
            logger.LogWarning("CA webhook received for {Connector} but no secret is configured", connectorId);
            return NotFound();
        }

        using var reader = new StreamReader(Request.Body, Encoding.UTF8);
        var body = await reader.ReadToEndAsync(ct);

        if (!IsAuthentic(body, secret))
        {
            // Recorded, because a wrong signature is either a misconfiguration or someone probing.
            audit.Append("ca:webhook", "ca.webhook.rejected", "ca_connector", connectorId.ToString(),
                "DENIED", new { reason = "signature mismatch" });
            await db.SaveChangesAsync(ct);
            return Unauthorized();
        }

        var connector = await db.CaConnectors.AsNoTracking().FirstOrDefaultAsync(c => c.Id == connectorId, ct);
        if (connector is null) return NotFound();

        // The callback may name a specific provider request; if it does not, every open request on
        // this connector is re-checked. Either way the CA is the one asked what happened.
        var providerRequestId = CaCallback.ExtractProviderRequestId(body);
        var open = await db.CertificateRequests
            .Where(r => r.CaConnectorId == connectorId
                        && (r.State == Domain.CertificateRequestState.PendingIssuance
                            || r.State == Domain.CertificateRequestState.SubmittedToCa)
                        && r.ProviderRequestId != null)
            .Where(r => providerRequestId == null || r.ProviderRequestId!.Contains(providerRequestId))
            .Select(r => r.Id)
            .Take(50)
            .ToListAsync(ct);

        audit.Append("ca:webhook", "ca.webhook.received", "ca_connector", connectorId.ToString(), "OK",
            new { connector.ConnectorType, providerRequestId, requests = open.Count });
        await db.SaveChangesAsync(ct);

        var polled = 0;
        foreach (var requestId in open)
        {
            try
            {
                await requests.PollOneAsync(requestId, ct);
                polled++;
            }
            catch (Exception ex)
            {
                // One failing request must not stop the others; the scheduled poll will retry it.
                logger.LogWarning(ex, "Webhook-triggered poll failed for request {Request}", requestId);
            }
        }

        return Accepted(new { matched = open.Count, polled });
    }

    /// <summary>
    /// Either an HMAC-SHA256 of the body in X-RemoteSSL-Signature, or the secret itself in
    /// X-RemoteSSL-Token for CAs that cannot sign. Both are compared in constant time.
    /// </summary>
    private bool IsAuthentic(string body, string secret)
    {
        if (Request.Headers.TryGetValue("X-RemoteSSL-Signature", out var signature))
        {
            var expected = Convert.ToHexString(
                HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body)));
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected),
                Encoding.UTF8.GetBytes(signature.ToString().Replace("sha256=", string.Empty).ToUpperInvariant()));
        }

        return Request.Headers.TryGetValue("X-RemoteSSL-Token", out var token)
               && CryptographicOperations.FixedTimeEquals(
                   Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(token.ToString()));
    }

}

/// <summary>
/// Domain validation as the operator drives it (design doc §18.1): see what the CA wants
/// published, publish it, then tell the CA to check.
/// </summary>
[ApiController]
[Route("api/v1/requests/{requestId:guid}/validations")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "CertOps")]
public class DomainValidationController(
    IRemoteSslDbContext db, DomainValidationService validations) : ControllerBase
{
    /// <summary>Refreshes the outstanding challenges from the CA and returns them.</summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<object>>> List(Guid requestId, CancellationToken ct)
    {
        try
        {
            var rows = await validations.RefreshAsync(requestId, ct);
            return Ok(rows.Select(v => new
            {
                v.Id, v.Domain, v.Method, State = v.State.ToString(),
                v.ExpectedDnsRecord, v.ExpectedHttpResponse, v.Detail,
                v.CreatedAt, v.SubmittedAt, v.CompletedAt, v.ExpiresAt
            }));
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            // The CA could not be reached, or handles validation elsewhere; show what is stored.
            var stored = await db.DomainValidations.AsNoTracking()
                .Where(v => v.CertificateRequestId == requestId)
                .Select(v => new
                {
                    v.Id, v.Domain, v.Method, State = v.State.ToString(),
                    v.ExpectedDnsRecord, v.ExpectedHttpResponse,
                    Detail = ex.Message,
                    v.CreatedAt, v.SubmittedAt, v.CompletedAt, v.ExpiresAt
                })
                .ToListAsync(ct);
            return Ok(stored);
        }
    }

    /// <summary>Tells the CA the proof is published and to verify it.</summary>
    [HttpPost("{validationId:guid}/submit")]
    public async Task<ActionResult<object>> Submit(Guid requestId, Guid validationId, CancellationToken ct)
    {
        try
        {
            var validation = await validations.SubmitAsync(validationId, Actor(), ct);
            return new { validation.Id, State = validation.State.ToString(), validation.Detail };
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }
    }

    private string Actor() => User.Identity?.Name is { Length: > 0 } name ? $"user:{name}" : "user:api";
}
