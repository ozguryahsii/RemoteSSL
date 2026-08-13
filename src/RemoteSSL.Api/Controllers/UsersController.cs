using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/users")]
[Authorize(Policy = "Admin")]
public class UsersController(IRemoteSslDbContext db, AuditWriter audit) : ControllerBase
{
    private static readonly PasswordHasher<string> Hasher = new();
    private static readonly string[] ValidRoles =
        ["Viewer", "CertificateOperator", "DeploymentOperator", "CertificateApprover",
         "SecurityAuditor", "PlatformAdministrator", "BreakGlassAdministrator"];

    public record CreateUserRequest(string Username, string Password, List<string> Roles);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.Users.AsNoTracking()
            .Select(u => new { u.Id, u.Username, u.RolesJson, u.Enabled, u.CreatedAt })
            .ToListAsync(ct);

    [HttpPost]
    public async Task<ActionResult<object>> Create(CreateUserRequest req, CancellationToken ct)
    {
        if (req.Password.Length < 8) return ValidationProblem("Password must be at least 8 characters.");
        var invalid = req.Roles.FirstOrDefault(r => !ValidRoles.Contains(r));
        if (invalid is not null) return ValidationProblem($"Unknown role '{invalid}'.");
        if (await db.Users.AnyAsync(u => u.Username == req.Username, ct))
            return Conflict(new ProblemDetails { Title = "Username already exists" });

        var user = new UserAccount
        {
            Id = Guid.NewGuid(),
            Username = req.Username,
            PasswordHash = Hasher.HashPassword(req.Username, req.Password),
            RolesJson = JsonSerializer.Serialize(req.Roles),
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.Users.Add(user);
        audit.Append("user:admin", "user.create", "user", user.Id.ToString(), "OK",
            new { req.Username, req.Roles });
        await db.SaveChangesAsync(ct);
        return new { user.Id };
    }

    public record UpdateUserRequest(string? Password, List<string>? Roles);

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateUserRequest req, CancellationToken ct)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return NotFound();
        if (!string.IsNullOrEmpty(req.Password))
        {
            if (req.Password.Length < 8) return ValidationProblem("Password must be at least 8 characters.");
            user.PasswordHash = Hasher.HashPassword(user.Username, req.Password);
        }
        if (req.Roles is not null)
        {
            var invalid = req.Roles.FirstOrDefault(r => !ValidRoles.Contains(r));
            if (invalid is not null) return ValidationProblem($"Unknown role '{invalid}'.");
            user.RolesJson = JsonSerializer.Serialize(req.Roles);
        }
        audit.Append("user:admin", "user.update", "user", id.ToString(), "OK");
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return NotFound();
        db.Users.Remove(user);
        audit.Append("user:admin", "user.delete", "user", id.ToString(), "OK", new { user.Username });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPatch("{id:guid}")]
    public async Task<IActionResult> SetEnabled(Guid id, [FromQuery] bool enabled, CancellationToken ct)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return NotFound();
        user.Enabled = enabled;
        audit.Append("user:admin", "user.set-enabled", "user", id.ToString(), enabled ? "ENABLED" : "DISABLED");
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}
