using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Policies;
using RemoteSSL.Application.Requests;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/certificates/requests")]
[Microsoft.AspNetCore.Authorization.Authorize(Policy = "CertOps")]
public class RequestsController(IRemoteSslDbContext db, CertificateRequestService service) : ControllerBase
{
    public record CreateRequest(
        string CommonName, List<string>? Sans, string KeyAlgorithm = "RSA", int KeySizeOrCurve = 2048,
        string KeyOrigin = "central", Guid? CaConnectorId = null, string? ProfileId = null,
        string RequestedBy = "api", Guid? TargetId = null, string? TargetKeyPath = null,
        string? Organization = null, string? OrganizationalUnit = null,
        string? Locality = null, string? State = null, string? Country = null,
        Guid? CertificateId = null, string? Environment = null, string? OwnerId = null,
        int? RequestedValidityDays = null);
    public record DecisionRequest(string Approver, bool Approve, string? Reason = null);
    public record UploadIssuedRequest(string CertPem, string? ChainPem);

    [HttpGet]
    public async Task<IEnumerable<object>> List([FromQuery] PageRequest page, CancellationToken ct) =>
        await db.CertificateRequests.AsNoTracking()
            .OrderByDescending(r => r.CreatedAt)
            .Select(r => new
            {
                r.Id, r.CommonName, r.SansJson, r.KeyAlgorithm, r.KeySizeOrCurve, r.KeyOrigin,
                State = r.State.ToString(), r.CaConnectorId, r.ProviderRequestId,
                r.ErrorMessage, r.IssuedVersionId, r.RequestedBy, r.Environment, r.OwnerId,
                r.CreatedAt, r.UpdatedAt
            }).ToPageAsync(page, Response, ct);

    [HttpPost]
    [ServiceFilter(typeof(Idempotency.IdempotencyFilter))]
    public async Task<ActionResult<object>> Create(CreateRequest req, CancellationToken ct)
    {
        try
        {
            var entity = await service.CreateAsync(req.CommonName, req.Sans ?? [], req.KeyAlgorithm,
                req.KeySizeOrCurve, req.KeyOrigin, req.CaConnectorId, req.ProfileId, req.RequestedBy, ct,
                req.TargetId, req.TargetKeyPath,
                new Application.Certificates.CertificateFactory.SubjectOptions(
                    req.Organization, req.OrganizationalUnit, req.Locality, req.State, req.Country),
                req.CertificateId, req.Environment, req.OwnerId, req.RequestedValidityDays);
            // Non-blocking policy findings (e.g. name overlap) travel with the response (§17.2).
            return new
            {
                entity.Id,
                State = entity.State.ToString(),
                entity.CsrPem,
                Warnings = service.LastWarnings.Where(w => !w.Blocking).Select(w => new { w.Rule, w.Message })
            };
        }
        catch (PolicyViolationException ex)
        {
            return UnprocessableEntity(new ProblemDetails
            {
                Title = ex.Message,
                Extensions = { ["findings"] = ex.Findings.Select(f => new { f.Rule, f.Message, f.Blocking }) }
            });
        }
        catch (ArgumentException ex) { return ValidationProblem(ex.Message); }
    }

    /// <summary>Maker-checker decision on a request awaiting approval (§19.1, §23.1).</summary>
    [HttpPost("{id:guid}/approve")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Approver")]
    public async Task<IActionResult> Approve(Guid id, DecisionRequest req, CancellationToken ct)
    {
        try
        {
            await service.ApproveAsync(id, req.Approver, req.Approve, req.Reason, IsBreakGlass(), ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return Conflict(new ProblemDetails { Title = ex.Message }); }
    }

    /// <summary>§23.3: break-glass administrators may override separation of duties.</summary>
    private bool IsBreakGlass() => User.IsInRole("BreakGlassAdministrator");

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var req = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (req is null) return NotFound();
        if (req.State == Domain.CertificateRequestState.Issued)
            return Conflict(new ProblemDetails { Title = "Issued requests cannot be deleted; the certificate lives in the inventory." });
        db.CertificateRequests.Remove(req);
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpGet("{id:guid}/csr")]
    public async Task<IActionResult> DownloadCsr(Guid id, CancellationToken ct)
    {
        var req = await db.CertificateRequests.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
        if (req?.CsrPem is null) return NotFound();
        return File(System.Text.Encoding.UTF8.GetBytes(req.CsrPem), "application/x-pem-file", $"{req.CommonName}.csr");
    }

    /// <summary>Manual CA fallback (design doc §18.4): operator uploads the signed certificate.</summary>
    [HttpPost("{id:guid}/certificate")]
    public async Task<IActionResult> UploadIssued(Guid id, UploadIssuedRequest req, CancellationToken ct)
    {
        try
        {
            await service.UploadIssuedAsync(id, req.CertPem, req.ChainPem, ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }
    }
}
