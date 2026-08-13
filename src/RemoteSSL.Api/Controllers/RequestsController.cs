using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
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
        string RequestedBy = "api", Guid? TargetId = null, string? TargetKeyPath = null);
    public record UploadIssuedRequest(string CertPem, string? ChainPem);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.CertificateRequests.AsNoTracking()
            .OrderByDescending(r => r.CreatedAt).Take(100)
            .Select(r => new
            {
                r.Id, r.CommonName, r.SansJson, r.KeyAlgorithm, r.KeySizeOrCurve, r.KeyOrigin,
                State = r.State.ToString(), r.CaConnectorId, r.ProviderRequestId,
                r.ErrorMessage, r.IssuedVersionId, r.RequestedBy, r.CreatedAt, r.UpdatedAt
            }).ToListAsync(ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateRequest req, CancellationToken ct)
    {
        try
        {
            var entity = await service.CreateAsync(req.CommonName, req.Sans ?? [], req.KeyAlgorithm,
                req.KeySizeOrCurve, req.KeyOrigin, req.CaConnectorId, req.ProfileId, req.RequestedBy, ct,
                req.TargetId, req.TargetKeyPath);
            return new { entity.Id, State = entity.State.ToString(), entity.CsrPem };
        }
        catch (ArgumentException ex) { return ValidationProblem(ex.Message); }
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
