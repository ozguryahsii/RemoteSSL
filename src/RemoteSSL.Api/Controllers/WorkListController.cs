using Microsoft.AspNetCore.Mvc;
using RemoteSSL.Application.Monitoring;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// What has to be done next, in one call. The screen that opens on this is the one that answers
/// the question people actually arrive with, rather than showing them five inventories and
/// leaving the sequence to them.
/// </summary>
[ApiController]
[Route("api/v1/worklist")]
public class WorkListController(WorkListService worklist) : ControllerBase
{
    [HttpGet]
    public async Task<IReadOnlyList<WorkItem>> Get(CancellationToken ct) => await worklist.BuildAsync(ct);
}
