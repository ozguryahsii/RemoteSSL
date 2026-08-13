using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Idempotency;

/// <summary>
/// Implements the <c>Idempotency-Key</c> header of design doc §27.2 for create endpoints:
/// a repeated key replays the first response instead of creating a second deployment or
/// request. The stored fingerprint of the body guards against a key being reused for a
/// different payload, which would otherwise hide a real mistake behind a cached answer.
/// </summary>
public class IdempotencyFilter : IAsyncActionFilter
{
    public const string HeaderName = "Idempotency-Key";

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var http = context.HttpContext;
        if (!http.Request.Headers.TryGetValue(HeaderName, out var headerValues))
        {
            await next();
            return;
        }

        var key = headerValues.ToString();
        if (string.IsNullOrWhiteSpace(key))
        {
            await next();
            return;
        }

        var db = http.RequestServices.GetRequiredService<IRemoteSslDbContext>();
        var endpoint = $"{http.Request.Method} {http.Request.Path}";
        var fingerprint = Fingerprint(context.ActionArguments);

        var existing = await db.IdempotencyRecords
            .FirstOrDefaultAsync(r => r.Key == key && r.Endpoint == endpoint, http.RequestAborted);
        if (existing is not null)
        {
            // An empty fingerprint means the body could not be hashed; replay without the check.
            if (fingerprint.Length > 0 && existing.RequestFingerprint.Length > 0
                && existing.RequestFingerprint != fingerprint)
            {
                context.Result = new ConflictObjectResult(new ProblemDetails
                {
                    Title = "This Idempotency-Key was already used with a different request body."
                });
                return;
            }

            context.Result = new ContentResult
            {
                StatusCode = existing.StatusCode,
                ContentType = "application/json",
                Content = existing.ResponseJson
            };
            http.Response.Headers["Idempotency-Replayed"] = "true";
            return;
        }

        var executed = await next();
        if (executed.Exception is not null) return;

        var (status, body) = Extract(executed.Result);
        if (status is < 200 or >= 300) return;

        db.IdempotencyRecords.Add(new IdempotencyRecord
        {
            Key = key,
            Endpoint = endpoint,
            RequestFingerprint = fingerprint,
            StatusCode = status,
            ResponseJson = body,
            CreatedAt = DateTimeOffset.UtcNow
        });
        try
        {
            await db.SaveChangesAsync(http.RequestAborted);
        }
        catch (DbUpdateException)
        {
            // A concurrent request with the same key won the unique index; the caller still
            // gets its own (identical) result, so this is not an error worth surfacing.
        }
    }

    /// <summary>
    /// Hashes the bound request payload. Framework-supplied arguments such as the
    /// CancellationToken are skipped — they carry no request meaning and are not
    /// serializable. If a payload cannot be serialized at all, the key is treated as
    /// unfingerprintable rather than failing the request.
    /// </summary>
    private static string Fingerprint(IDictionary<string, object?> arguments)
    {
        var payload = arguments
            .Where(a => a.Value is not CancellationToken)
            .OrderBy(a => a.Key, StringComparer.Ordinal)
            .ToDictionary(a => a.Key, a => a.Value);
        try
        {
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        }
        catch (NotSupportedException)
        {
            return string.Empty;
        }
    }

    private static (int Status, string Body) Extract(IActionResult? result) => result switch
    {
        ObjectResult o => (o.StatusCode ?? 200, JsonSerializer.Serialize(o.Value,
            new JsonSerializerOptions(JsonSerializerDefaults.Web))),
        StatusCodeResult s => (s.StatusCode, "null"),
        _ => (0, "null")
    };
}
