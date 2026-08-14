using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace RemoteSSL.Api.Security;

/// <summary>
/// Request rate limiting and security response headers (design doc §4.2, §30.2). Limits are
/// per caller — the authenticated user when there is one, otherwise the remote address — so
/// one noisy client cannot starve the rest. Runner traffic gets its own, larger bucket: a
/// fleet polling for jobs is normal load, not abuse.
/// </summary>
public static class RateLimitingSetup
{
    public const string RunnerPolicy = "runner";

    public static void AddRemoteSslRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var permitPerMinute = configuration.GetValue("Security:RateLimit:PermitsPerMinute", 300);
        var runnerPermitPerMinute = configuration.GetValue("Security:RateLimit:RunnerPermitsPerMinute", 1200);
        var queueLimit = configuration.GetValue("Security:RateLimit:QueueLimit", 0);

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, ct) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        ((int)retryAfter.TotalSeconds).ToString(CultureInfo.InvariantCulture);
                }
                await context.HttpContext.Response.WriteAsJsonAsync(new
                {
                    title = "Too many requests. Slow down and retry.",
                    status = StatusCodes.Status429TooManyRequests
                }, ct);
            };

            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                // Health and metrics are scraped by infrastructure on a schedule; limiting them
                // would make monitoring look like an outage.
                var path = context.Request.Path.Value ?? string.Empty;
                if (path.StartsWith("/health", StringComparison.OrdinalIgnoreCase)
                    || path.StartsWith("/metrics", StringComparison.OrdinalIgnoreCase))
                {
                    return RateLimitPartition.GetNoLimiter("infrastructure");
                }

                var isRunner = path.StartsWith("/api/v1/runners", StringComparison.OrdinalIgnoreCase);
                var key = context.User.Identity?.Name
                          ?? context.Connection.RemoteIpAddress?.ToString()
                          ?? "anonymous";

                return RateLimitPartition.GetFixedWindowLimiter($"{(isRunner ? "runner" : "api")}:{key}", _ =>
                    new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = isRunner ? runnerPermitPerMinute : permitPerMinute,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = queueLimit,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst
                    });
            });
        });
    }

    /// <summary>
    /// Response hardening headers. The API is token-based and serves no HTML, so the useful
    /// set is about not being framed, not sniffing content types, and not leaking URLs in
    /// referrers — CSRF itself is structurally absent without cookie authentication.
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Cross-Origin-Resource-Policy"] = "same-origin";
            await next();
        });
}
