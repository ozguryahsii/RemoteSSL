using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Deployments;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/deployments")]
public class DeploymentsController(IRemoteSslDbContext db, DeploymentService service) : ControllerBase
{
    public record CreateDeploymentRequest(
        Guid CertificateVersionId, List<Guid> BindingIds, string Strategy = "sequential",
        string RequestedBy = "api", bool ApprovalRequired = false);
    public record DecisionRequest(string Approver, bool Approve = true, string? Reason = null);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.DeploymentJobs.AsNoTracking()
            .OrderByDescending(j => j.CreatedAt).Take(100)
            .Select(j => new
            {
                j.Id, Status = j.Status.ToString(), j.Strategy, j.RequestedBy, j.ApprovedBy,
                Certificate = j.CertificateVersion.Certificate.CommonName,
                Thumbprint = j.CertificateVersion.Sha256Thumbprint,
                TargetCount = j.Targets.Count, j.CreatedAt, j.StartedAt, j.CompletedAt, j.CorrelationId
            }).ToListAsync(ct);

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<object>> Get(Guid id, CancellationToken ct)
    {
        var job = await db.DeploymentJobs.AsNoTracking()
            .Where(j => j.Id == id)
            .Select(j => new
            {
                j.Id, Status = j.Status.ToString(), j.Strategy, j.RequestedBy, j.ApprovedBy,
                Certificate = j.CertificateVersion.Certificate.CommonName,
                j.CreatedAt, j.StartedAt, j.CompletedAt, j.CorrelationId,
                Targets = j.Targets.Select(t => new
                {
                    t.Id, Status = t.Status.ToString(),
                    Target = t.DeploymentBinding.CertificateStore.Target.Name,
                    Adapter = t.DeploymentBinding.CertificateStore.Target.AdapterType,
                    Store = t.DeploymentBinding.CertificateStore.StorePath,
                    Steps = t.Steps.OrderBy(s => s.CompletedAt).Select(s => new
                    {
                        Step = s.StepType.ToString(), Status = s.Status.ToString(), s.SafeLog, s.CompletedAt
                    })
                })
            }).FirstOrDefaultAsync(ct);
        return job is null ? NotFound() : job;
    }

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateDeploymentRequest req, CancellationToken ct)
    {
        try
        {
            var job = await service.CreateJobAsync(req.CertificateVersionId, req.BindingIds,
                req.Strategy, req.RequestedBy, req.ApprovalRequired, ct);
            return CreatedAtAction(nameof(Get), new { id = job.Id }, new { job.Id, Status = job.Status.ToString() });
        }
        catch (KeyNotFoundException ex) { return NotFound(new ProblemDetails { Title = ex.Message }); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }
    }

    [HttpPost("{id:guid}/approve")]
    public async Task<IActionResult> Approve(Guid id, DecisionRequest req, CancellationToken ct)
    {
        try
        {
            await service.ApproveAsync(id, req.Approver, req.Approve, req.Reason, ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    [HttpPost("{id:guid}/execute")]
    public async Task<IActionResult> Execute(Guid id, CancellationToken ct)
    {
        try
        {
            await service.ExecuteAsync(id, ct);
            return Accepted();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    [HttpGet("approvals/pending")]
    public async Task<IEnumerable<object>> PendingApprovals(CancellationToken ct) =>
        await db.ApprovalRequests.AsNoTracking()
            .Where(a => a.Status == "Pending")
            .Select(a => new { a.Id, a.DeploymentJobId, a.RequestedBy, a.CreatedAt })
            .ToListAsync(ct);
}
