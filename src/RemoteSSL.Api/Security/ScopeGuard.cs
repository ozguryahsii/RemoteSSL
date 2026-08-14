using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Security;

namespace RemoteSSL.Api.Security;

/// <summary>
/// Enforces the §24.2 scope model on the operations that actually touch systems. Roles are
/// checked by the framework's policies; this adds the "where" — environment, target group and
/// adapter — and records refusals, because an authorization denial is exactly the kind of
/// event §25 wants in the trail.
/// </summary>
public class ScopeGuard(IRemoteSslDbContext db, AuditWriter audit)
{
    /// <summary>
    /// Throws <see cref="ScopeDeniedException"/> when the caller's scopes forbid the request.
    /// A caller without an account (auth disabled, or a service token) is not scope-limited.
    /// </summary>
    public async Task EnsureAllowedAsync(ClaimsPrincipal caller, ScopeRequest request, CancellationToken ct)
    {
        var username = caller.Identity?.Name;
        if (string.IsNullOrWhiteSpace(username)) return;

        var scopesJson = await db.Users.AsNoTracking()
            .Where(u => u.Username == username)
            .Select(u => u.ScopesJson)
            .FirstOrDefaultAsync(ct);
        var rules = ScopeEvaluator.Parse(scopesJson);
        if (ScopeEvaluator.IsAllowed(rules, request)) return;

        audit.Append($"user:{username}", "authorization.denied", "scope", request.Action, "DENIED",
            new { request.Environment, request.TargetGroup, request.Adapter, request.ApprovalRequired });
        await db.SaveChangesAsync(ct);

        throw new ScopeDeniedException(
            $"Your scope does not permit '{request.Action}'"
            + (request.Environment is null ? "" : $" in {request.Environment}")
            + (request.TargetGroup is null ? "" : $" for target group {request.TargetGroup}")
            + (request.Adapter is null ? "" : $" using the {request.Adapter} adapter")
            + ".");
    }
}

/// <summary>Raised when scope rules refuse an operation the caller's role would otherwise allow.</summary>
public class ScopeDeniedException(string message) : Exception(message);
