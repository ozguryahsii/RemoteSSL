using System.Security.Claims;
using RemoteSSL.Application.Auditing;

namespace RemoteSSL.Api.Security;

/// <summary>
/// Fills the per-request audit context (design doc §25.1) so every audit row written while
/// handling the request records who was there, from where, and in which session — without any
/// call site having to thread that through. Background work has no request, and its rows simply
/// carry no context.
/// </summary>
public class AuditContextMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext http, AuditContext context)
    {
        // The session id comes from the token when the identity provider issues one; falling back
        // to the JWT id keeps distinct logins distinguishable for local accounts too.
        context.SessionId = http.User.FindFirstValue("sid")
                            ?? http.User.FindFirstValue("jti");
        context.SourceIp = http.Connection.RemoteIpAddress?.ToString();
        context.UserAgent = Truncate(http.Request.Headers.UserAgent.ToString(), 512);

        await next(http);
    }

    private static string? Truncate(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= max ? value : value[..max];
}

public static class AuditContextMiddlewareExtensions
{
    /// <summary>
    /// Registers the audit context filler. Must run after authentication so the session claim is
    /// available, and before the endpoints that write audit rows.
    /// </summary>
    public static IApplicationBuilder UseAuditContext(this IApplicationBuilder app) =>
        app.UseMiddleware<AuditContextMiddleware>();
}
