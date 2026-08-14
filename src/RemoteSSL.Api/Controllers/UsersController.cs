using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Security;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Api.Controllers;

[ApiController]
[Route("api/v1/users")]
[Authorize(Policy = "Admin")]
public class UsersController(IRemoteSslDbContext db, AuditWriter audit) : ControllerBase
{
    private static readonly PasswordHasher<string> Hasher = new();
    private static readonly string[] ValidRoles = Security.AuthenticationSetup.Roles;

    public record CreateUserRequest(
        string Username, string Password, List<string> Roles,
        List<ScopeRule>? Scopes = null, string? ExternalSubject = null);

    [HttpGet]
    public async Task<IEnumerable<object>> List(CancellationToken ct) =>
        await db.Users.AsNoTracking()
            .Select(u => new { u.Id, u.Username, u.RolesJson, u.ScopesJson, u.ExternalSubject, u.Enabled, u.CreatedAt })
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
            ScopesJson = JsonSerializer.Serialize(req.Scopes ?? []),
            ExternalSubject = req.ExternalSubject,
            CreatedAt = DateTimeOffset.UtcNow
        };
        db.Users.Add(user);
        audit.Append("user:admin", "user.create", "user", user.Id.ToString(), "OK",
            new { req.Username, req.Roles });
        await db.SaveChangesAsync(ct);
        return new { user.Id };
    }

    public record UpdateUserRequest(
        string? Password, List<string>? Roles,
        List<ScopeRule>? Scopes = null, string? ExternalSubject = null, bool ClearExternalSubject = false);

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
        if (req.Scopes is not null) user.ScopesJson = JsonSerializer.Serialize(req.Scopes);
        if (req.ClearExternalSubject) user.ExternalSubject = null;
        else if (req.ExternalSubject is not null) user.ExternalSubject = req.ExternalSubject;
        audit.Append("user:admin", "user.update", "user", id.ToString(), "OK",
            new { roles = req.Roles, scopes = req.Scopes?.Count, federated = user.ExternalSubject is not null });
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
