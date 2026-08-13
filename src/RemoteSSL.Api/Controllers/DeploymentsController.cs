using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Deployments;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/deployments")]
public class DeploymentsController(
    IRemoteSslDbContext db, DeploymentService service, DeploymentPlanner planner) : ControllerBase
{
    public record CreateDeploymentRequest(
        Guid CertificateVersionId, List<Guid> BindingIds, string Strategy = "sequential",
        string RequestedBy = "api", bool ApprovalRequired = false, bool AutoExecute = false,
        int MaxConcurrency = 0);
    public record DecisionRequest(string Approver, bool Approve = true, string? Reason = null);
    public record PlanRequest(
        Guid CertificateVersionId, List<Guid> BindingIds, string Strategy = "sequential",
        int MaxConcurrency = 0, bool ApprovalRequired = false);
    public record ActorRequest(string RequestedBy = "api");
    public record CancelRequest(string RequestedBy = "api", string? Reason = null);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.DeploymentJobs.AsNoTracking()
            .OrderByDescending(j => j.CreatedAt).Take(100)
            .Select(j => new
            {
                j.Id, Status = j.Status.ToString(), j.Strategy, j.MaxConcurrency, j.RequestedBy, j.ApprovedBy,
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

    /// <summary>
    /// Impact preview before committing to a deployment (NFR-008): which targets change,
    /// what they serve today, the execution order, the governance that applies and anything
    /// that would block the run. Read-only — nothing is created.
    /// </summary>
    [HttpPost("plan")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
    public async Task<ActionResult<DeploymentPlan>> Plan(PlanRequest req, CancellationToken ct)
    {
        try
        {
            return await planner.PlanAsync(req.CertificateVersionId, req.BindingIds, req.Strategy,
                req.MaxConcurrency, req.ApprovalRequired, ct);
        }
        catch (KeyNotFoundException ex) { return NotFound(new ProblemDetails { Title = ex.Message }); }
    }

    /// <summary>Merged progress timeline of a job: audit events, per-target steps and runner jobs (§27.1).</summary>
    [HttpGet("{id:guid}/events")]
    public async Task<ActionResult<object>> Events(Guid id, CancellationToken ct)
    {
        var job = await db.DeploymentJobs.AsNoTracking()
            .Where(j => j.Id == id)
            .Select(j => new { j.Id, j.CorrelationId, j.CreatedAt })
            .FirstOrDefaultAsync(ct);
        if (job is null) return NotFound();

        var events = new List<object>();

        var audits = await db.AuditEvents.AsNoTracking()
            .Where(e => e.ObjectType == "deployment_job" && e.ObjectId == id.ToString())
            .Select(e => new { e.Timestamp, e.Actor, e.Action, e.Result, e.DetailsJson })
            .ToListAsync(ct);
        events.AddRange(audits.Select(e => (object)new
        {
            At = e.Timestamp, Kind = "job", Source = e.Actor, Name = e.Action, e.Result, Detail = e.DetailsJson
        }));

        var steps = await db.DeploymentSteps.AsNoTracking()
            .Where(s => s.DeploymentJobTarget.DeploymentJobId == id)
            .Select(s => new
            {
                s.CompletedAt, s.StartedAt, Step = s.StepType.ToString(), Status = s.Status.ToString(),
                s.SafeLog, s.RetryCount,
                Target = s.DeploymentJobTarget.DeploymentBinding.CertificateStore.Target.Name
            })
            .ToListAsync(ct);
        events.AddRange(steps.Select(s => (object)new
        {
            At = s.CompletedAt ?? s.StartedAt ?? job.CreatedAt, Kind = "step", Source = s.Target,
            Name = s.Step, Result = s.Status, Detail = s.SafeLog
        }));

        var runnerJobs = await db.RunnerJobs.AsNoTracking()
            .Where(r => r.CorrelationId == job.CorrelationId)
            .Select(r => new { r.Id, r.JobType, r.Status, r.CreatedAt, r.ClaimedAt, r.CompletedAt })
            .ToListAsync(ct);
        events.AddRange(runnerJobs.Select(r => (object)new
        {
            At = r.CompletedAt ?? r.ClaimedAt ?? r.CreatedAt, Kind = "runner-job", Source = r.JobType,
            Name = r.Id.ToString(), Result = r.Status, Detail = (string?)null
        }));

        return new
        {
            JobId = id,
            job.CorrelationId,
            Events = events.OrderBy(e => (DateTimeOffset)e.GetType().GetProperty("At")!.GetValue(e)!).ToList()
        };
    }

    /// <summary>Cancels a job that has not started, releasing its bindings (§21.3).</summary>
    [HttpPost("{id:guid}/cancel")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
    public async Task<IActionResult> Cancel(Guid id, CancelRequest req, CancellationToken ct)
    {
        try
        {
            await service.CancelAsync(id, req.RequestedBy, req.Reason, ct);
            return NoContent();
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    /// <summary>Releases the next wave of a canary/manual deployment (§21.4).</summary>
    [HttpPost("{id:guid}/continue")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
    public async Task<ActionResult<object>> Continue(Guid id, ActorRequest req, CancellationToken ct)
    {
        try
        {
            var dispatched = await service.ContinueAsync(id, req.RequestedBy, ct);
            return new { Dispatched = dispatched };
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    /// <summary>
    /// Manual rollback (FR-018): re-deploys the previous certificate version to the targets
    /// this job changed, through the full transactional pipeline.
    /// </summary>
    [HttpPost("{id:guid}/rollback")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
    public async Task<ActionResult<object>> Rollback(Guid id, ActorRequest req, CancellationToken ct)
    {
        try
        {
            var (jobs, skipped) = await service.RollbackAsync(id, req.RequestedBy, ct);
            return new { RollbackJobs = jobs, Skipped = skipped };
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new ProblemDetails { Title = ex.Message }); }
    }

    [HttpPost]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
    [ServiceFilter(typeof(Idempotency.IdempotencyFilter))]
    public async Task<ActionResult<object>> Create(CreateDeploymentRequest req, CancellationToken ct)
    {
        try
        {
            var job = await service.CreateJobAsync(req.CertificateVersionId, req.BindingIds,
                req.Strategy, req.RequestedBy, req.ApprovalRequired, ct, req.MaxConcurrency);
            if (req.AutoExecute && !req.ApprovalRequired) await service.ExecuteAsync(job.Id, ct);
            return CreatedAtAction(nameof(Get), new { id = job.Id }, new { job.Id, Status = job.Status.ToString() });
        }
        catch (KeyNotFoundException ex) { return NotFound(new ProblemDetails { Title = ex.Message }); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return UnprocessableEntity(new ProblemDetails { Title = ex.Message });
        }
    }

    [HttpPost("{id:guid}/approve")]
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "Approver")]
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
    [Microsoft.AspNetCore.Authorization.Authorize(Policy = "DeployOps")]
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
