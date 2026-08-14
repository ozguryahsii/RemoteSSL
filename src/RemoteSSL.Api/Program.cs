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

builder.Services.AddControllers();
// Idempotency-Key support for create endpoints (§27.2).
builder.Services.AddScoped<RemoteSSL.Api.Idempotency.IdempotencyFilter>();
// §24.2 attribute-based scope checks on operations that touch real systems.
builder.Services.AddScoped<ScopeGuard>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddRemoteSslInfrastructure(builder.Configuration);

builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("Database")!, name: "postgres")
    .AddRabbitMQ(rabbitConnectionString: builder.Configuration.GetConnectionString("RabbitMq")!, name: "rabbitmq")
    .AddRedis(builder.Configuration.GetConnectionString("Redis")!, name: "redis");

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

app.UseSecurityHeaders();
app.UseCors();
app.UseRateLimiter();
if (authEnabled) app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/health").AllowAnonymous();

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
