using RemoteSSL.Application.Observability;

namespace RemoteSSL.Api.Security;

/// <summary>
/// Design doc §27.2: "Correlation-ID tüm requestlerde."
///
/// A caller that already has a correlation id — a CI pipeline renewing a certificate, an ITSM
/// change record, another RemoteSSL instance — passes it in, and everything the request writes
/// (audit rows, deployment jobs, runner jobs, events, OpenTelemetry spans) is stamped with it
/// rather than with a fresh one. Without this, the §32.2 end-to-end trace starts at RemoteSSL's
/// front door and the work cannot be joined back to whatever asked for it.
///
/// The id is always echoed on the response, including on the requests that did not supply one, so
/// a caller can record the id RemoteSSL chose and look the operation up later.
/// </summary>
public class CorrelationIdMiddleware(RequestDelegate next)
{
    public const string HeaderName = "Correlation-ID";

    /// <summary>Also accepted, because clients and gateways commonly send this spelling.</summary>
    public const string LegacyHeaderName = "X-Correlation-ID";

    /// <summary>Bounded so a hostile or broken client cannot push arbitrary data into audit rows.</summary>
    private const int MaxLength = 128;

    public async Task InvokeAsync(HttpContext http)
    {
        var supplied = First(http, HeaderName) ?? First(http, LegacyHeaderName);
        var correlationId = Sanitize(supplied) ?? TraceContext.NewCorrelationId();

        // Echo before the response starts: once a handler begins writing, headers are frozen.
        http.Response.OnStarting(() =>
        {
            http.Response.Headers[HeaderName] = correlationId;
            return Task.CompletedTask;
        });

        // The scope is what makes the id the ambient default for everything below, so call sites
        // do not have to accept and forward it.
        using var trace = TraceContext.Begin($"http {http.Request.Method} {http.Request.Path}", correlationId);
        await next(http);
    }

    private static string? First(HttpContext http, string header) =>
        http.Request.Headers.TryGetValue(header, out var values) ? values.FirstOrDefault() : null;

    /// <summary>
    /// Keeps only what can safely be stored and echoed. A correlation id ends up in audit rows,
    /// log lines and a response header, so control characters and newlines — the ingredients of
    /// header injection and log forging — are rejected rather than stripped: a caller that sent
    /// one has a bug worth surfacing, and silently rewriting their id would break their join.
    /// </summary>
    private static string? Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var trimmed = value.Trim();
        if (trimmed.Length > MaxLength) return null;

        foreach (var c in trimmed)
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.' or ':')) return null;

        return trimmed;
    }
}

public static class CorrelationIdMiddlewareExtensions
{
    /// <summary>
    /// Registers correlation id handling. Runs early so everything downstream — including the
    /// audit context and any failure handler — shares the same id.
    /// </summary>
    public static IApplicationBuilder UseCorrelationId(this IApplicationBuilder app) =>
        app.UseMiddleware<CorrelationIdMiddleware>();
}
