using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RemoteSSL.Api.Controllers;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddRemoteSslInfrastructure(builder.Configuration);

builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("Database")!, name: "postgres")
    .AddRabbitMQ(rabbitConnectionString: builder.Configuration.GetConnectionString("RabbitMq")!, name: "rabbitmq")
    .AddRedis(builder.Configuration.GetConnectionString("Redis")!, name: "redis");

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? ["http://localhost:5173"])
    .AllowAnyHeader()
    .AllowAnyMethod()));

var authEnabled = builder.Configuration.GetValue("Auth:Enabled", false);
if (authEnabled)
{
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = "remotessl",
            ValidAudience = "remotessl",
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Auth:JwtSecret"]
                    ?? throw new InvalidOperationException("Auth:JwtSecret is required when Auth:Enabled=true")))
        });
    builder.Services.AddAuthorizationBuilder()
        .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser().Build())
        // Role policies per design doc §24.1
        .AddPolicy("Admin", p => p.RequireRole("PlatformAdministrator"))
        .AddPolicy("CertOps", p => p.RequireRole("CertificateOperator", "PlatformAdministrator"))
        .AddPolicy("DeployOps", p => p.RequireRole("DeploymentOperator", "PlatformAdministrator"))
        .AddPolicy("Approver", p => p.RequireRole("CertificateApprover", "PlatformAdministrator"));
}
else
{
    // Auth disabled (dev): all policies pass so [Authorize(Policy=...)] attributes stay inert.
    builder.Services.AddAuthorizationBuilder()
        .AddPolicy("Admin", p => p.RequireAssertion(_ => true))
        .AddPolicy("CertOps", p => p.RequireAssertion(_ => true))
        .AddPolicy("DeployOps", p => p.RequireAssertion(_ => true))
        .AddPolicy("Approver", p => p.RequireAssertion(_ => true));
}

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();
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
    await AuthController.SeedAdminAsync(
        scope.ServiceProvider.GetRequiredService<IRemoteSslDbContext>(), app.Configuration, CancellationToken.None);
}

app.Run();
