using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

/// <summary>
/// Local-user JWT authentication (F10 baseline). Enabled via Auth:Enabled; OIDC/SSO
/// federation replaces this in enterprise deployments. Roles follow design doc §24.1.
/// </summary>
[ApiController]
[Route("api/v1/auth")]
[AllowAnonymous]
public class AuthController(IRemoteSslDbContext db, IConfiguration config, AuditWriter audit) : ControllerBase
{
    private static readonly PasswordHasher<string> Hasher = new();

    public record LoginRequest(string Username, string Password);

    [HttpPost("login")]
    public async Task<ActionResult<object>> Login(LoginRequest req, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Username == req.Username && u.Enabled, ct);
        if (user is null || Hasher.VerifyHashedPassword(req.Username, user.PasswordHash, req.Password)
            == PasswordVerificationResult.Failed)
        {
            audit.Append($"user:{req.Username}", "auth.login", "user", null, "FAILED");
            await db.SaveChangesAsync(ct);
            return Unauthorized(new ProblemDetails { Title = "Invalid credentials" });
        }

        var roles = JsonSerializer.Deserialize<string[]>(user.RolesJson) ?? [];
        var claims = new List<Claim> { new(ClaimTypes.Name, user.Username) };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            config["Auth:JwtSecret"] ?? throw new InvalidOperationException("Auth:JwtSecret missing")));
        var token = new JwtSecurityToken(
            issuer: "remotessl", audience: "remotessl",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(8),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

        audit.Append($"user:{user.Username}", "auth.login", "user", user.Id.ToString(), "OK");
        await db.SaveChangesAsync(ct);
        return new { Token = new JwtSecurityTokenHandler().WriteToken(token), Roles = roles };
    }

    /// <summary>Seeds the admin user from configuration on first call (idempotent).</summary>
    public static async Task SeedAdminAsync(IRemoteSslDbContext db, IConfiguration config, CancellationToken ct)
    {
        if (await db.Users.AnyAsync(ct)) return;
        var password = config["Auth:AdminPassword"];
        if (string.IsNullOrEmpty(password)) return;
        var username = config["Auth:AdminUsername"] ?? "admin";
        db.Users.Add(new UserAccount
        {
            Id = Guid.NewGuid(),
            Username = username,
            PasswordHash = Hasher.HashPassword(username, password),
            RolesJson = """["PlatformAdministrator","CertificateOperator","DeploymentOperator","CertificateApprover"]""",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }
}
