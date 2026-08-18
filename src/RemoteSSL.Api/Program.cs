using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RemoteSSL.Api.Controllers;
using RemoteSSL.Api.Security;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Observability;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using RemoteSSL.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// So the control plane can run as a Windows service on the server that manages the estate.
// No effect on other platforms.
builder.Services.AddWindowsService(o => o.ServiceName = "RemoteSSL API");

builder.Services.AddControllers();
// Idempotency-Key support for create endpoints (§27.2).
builder.Services.AddScoped<RemoteSSL.Api.Idempotency.IdempotencyFilter>();
// §24.2 attribute-based scope checks on operations that touch real systems.
builder.Services.AddScoped<ScopeGuard>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddRemoteSslInfrastructure(builder.Configuration);

// The database is required; the queue and the cache are checked only where they are configured.
// An install that leaves them out must not report itself unhealthy for something it never uses —
// a health endpoint that is always red tells the operator nothing.
var health = builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("Database")!, name: "postgres");
var rabbit = builder.Configuration.GetConnectionString("RabbitMq");
if (!string.IsNullOrWhiteSpace(rabbit)) health.AddRabbitMQ(rabbitConnectionString: rabbit, name: "rabbitmq");
var redis = builder.Configuration.GetConnectionString("Redis");
if (!string.IsNullOrWhiteSpace(redis)) health.AddRedis(redis, name: "redis");

// §32.2 distributed tracing: the RemoteSSL activity source carries the correlation id
// that spans certificate request → CA → deployment job → runner → target. Exported over
// OTLP only when an endpoint is configured, so the default install needs no collector.
var otlpEndpoint = builder.Configuration["Observability:OtlpEndpoint"];
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("remotessl-api"))
    .WithTracing(t =>
    {
        t.AddSource(TraceContext.Source.Name)
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation();
        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
            t.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
    });

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? ["http://localhost:5173"])
    .AllowAnyHeader()
    .AllowAnyMethod()));

var authEnabled = builder.Configuration.GetValue("Auth:Enabled", false);
builder.Services.AddRemoteSslAuthentication(builder.Configuration);

// §30.2: bound request rates so a stolen token or a loop cannot hammer the control plane.
builder.Services.AddRemoteSslRateLimiting(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// §27.2: honour an inbound Correlation-ID and echo it, so a caller's trace and RemoteSSL's
// join up. First in the pipeline — everything after it inherits the id.
app.UseCorrelationId();
app.UseSecurityHeaders();
app.UseCors();
app.UseRateLimiter();
if (authEnabled) app.UseAuthentication();
// After authentication so the session claim is present, before the endpoints that audit (§25.1).
app.UseAuditContext();
// §35: resolve the caller's tenant before any tenant-scoped query runs.
app.UseTenantContext();
app.UseAuthorization();

// A single-server install (a test box, for instance) puts the built UI in wwwroot and is then
// served from here: same origin as the API, so there is no second web server to set up and no
// CORS list to keep in step. Absent that folder — the development setup, where Vite serves the
// UI — nothing below changes.
if (File.Exists(Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index.html")))
{
    app.UseDefaultFiles();
    app.UseStaticFiles();
}

app.MapControllers();
app.MapHealthChecks("/health").AllowAnonymous();

// The UI routes on paths the API does not serve (/servers, /certificates …); a browser asking
// for one directly must get the application, not a 404.
if (File.Exists(Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index.html")))
    app.MapFallbackToFile("index.html").AllowAnonymous();

using (var scope = app.Services.CreateScope())
{
    // Apply pending EF migrations on startup so local/dev setups don't need dotnet-ef.
    // Disable with Database:MigrateOnStartup=false when migrations are managed externally.
    if (app.Configuration.GetValue("Database:MigrateOnStartup", true))
    {
        var db = scope.ServiceProvider.GetRequiredService<RemoteSSL.Infrastructure.Persistence.RemoteSslDbContext>();
        await db.Database.MigrateAsync();
    }
    await CertificatePoliciesController.SeedDefaultAsync(
        scope.ServiceProvider.GetRequiredService<IRemoteSslDbContext>(), CancellationToken.None);
    await AuthController.SeedAdminAsync(
        scope.ServiceProvider.GetRequiredService<IRemoteSslDbContext>(), app.Configuration, CancellationToken.None);
}

app.Run();
