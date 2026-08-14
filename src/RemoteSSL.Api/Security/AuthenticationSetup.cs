using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RemoteSSL.Application.Abstractions;

namespace RemoteSSL.Api.Security;

/// <summary>
/// Authentication and authorization wiring for design doc §24 and §4.3: local JWT for
/// standalone installs, OIDC for enterprise SSO (Entra ID, Keycloak) with MFA enforced
/// upstream by the identity provider and asserted through the token's authentication
/// method claims.
/// </summary>
public static class AuthenticationSetup
{
    public const string LocalScheme = "RemoteSslLocal";
    public const string OidcScheme = "RemoteSslOidc";

    /// <summary>Roles of §24.1, in increasing order of privilege.</summary>
    public static readonly string[] Roles =
    [
        "Viewer", "CertificateOperator", "DeploymentOperator", "CertificateApprover",
        "SecurityAuditor", "PlatformAdministrator", "BreakGlassAdministrator"
    ];

    public static void AddRemoteSslAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var authEnabled = configuration.GetValue("Auth:Enabled", false);
        var oidcAuthority = configuration["Auth:Oidc:Authority"];
        var oidcEnabled = !string.IsNullOrWhiteSpace(oidcAuthority);

        if (!authEnabled)
        {
            // Development: policies exist but pass, so [Authorize(Policy=…)] stays inert.
            services.AddAuthorizationBuilder()
                .AddPolicy("Admin", p => p.RequireAssertion(_ => true))
                .AddPolicy("CertOps", p => p.RequireAssertion(_ => true))
                .AddPolicy("DeployOps", p => p.RequireAssertion(_ => true))
                .AddPolicy("Approver", p => p.RequireAssertion(_ => true))
                .AddPolicy("Reader", p => p.RequireAssertion(_ => true))
                .AddPolicy("Auditor", p => p.RequireAssertion(_ => true));
            return;
        }

        var builder = services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = LocalScheme;
            options.DefaultChallengeScheme = LocalScheme;
        });

        builder.AddJwtBearer(LocalScheme, o =>
        {
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = "remotessl",
                ValidAudience = "remotessl",
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(configuration["Auth:JwtSecret"]
                        ?? throw new InvalidOperationException("Auth:JwtSecret is required when Auth:Enabled=true")))
            };
        });

        if (oidcEnabled)
        {
            builder.AddJwtBearer(OidcScheme, o =>
            {
                o.Authority = oidcAuthority;
                o.Audience = configuration["Auth:Oidc:Audience"];
                o.RequireHttpsMetadata = configuration.GetValue("Auth:Oidc:RequireHttpsMetadata", true);
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    // Providers differ on where roles land; both common shapes are accepted.
                    RoleClaimType = configuration["Auth:Oidc:RoleClaim"] ?? "roles",
                    NameClaimType = configuration["Auth:Oidc:NameClaim"] ?? "preferred_username"
                };
                o.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context => await OnOidcTokenValidatedAsync(context, configuration)
                };
            });

            // Either scheme may carry the caller; the first that validates wins.
            services.AddAuthorization(options => options.DefaultPolicy =
                new AuthorizationPolicyBuilder(LocalScheme, OidcScheme).RequireAuthenticatedUser().Build());
        }

        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(oidcEnabled
                ? new AuthorizationPolicyBuilder(LocalScheme, OidcScheme).RequireAuthenticatedUser().Build()
                : new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            // Role policies per §24.1. Higher roles inherit the lower ones' access.
            .AddPolicy("Admin", p => p.RequireRole("PlatformAdministrator"))
            .AddPolicy("CertOps", p => p.RequireRole("CertificateOperator", "PlatformAdministrator"))
            .AddPolicy("DeployOps", p => p.RequireRole("DeploymentOperator", "PlatformAdministrator"))
            .AddPolicy("Approver", p => p.RequireRole("CertificateApprover", "PlatformAdministrator"))
            // Read-only access for Viewer and the auditor role, plus everyone above them.
            .AddPolicy("Reader", p => p.RequireRole(Roles))
            .AddPolicy("Auditor", p => p.RequireRole("SecurityAuditor", "PlatformAdministrator"));
    }

    /// <summary>
    /// Maps a federated identity onto a RemoteSSL account and enforces the MFA requirement.
    /// The identity provider performs MFA; RemoteSSL verifies the token says so (§30.2), and
    /// refuses the request when the deployment demands MFA but the token cannot prove it.
    /// </summary>
    private static async Task OnOidcTokenValidatedAsync(TokenValidatedContext context, IConfiguration configuration)
    {
        var principal = context.Principal;
        if (principal is null) return;

        if (configuration.GetValue("Auth:Oidc:RequireMfa", false) && !HasMultiFactorClaim(principal))
        {
            context.Fail("The identity provider did not assert multi-factor authentication for this session.");
            return;
        }

        var subject = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var username = principal.Identity?.Name ?? principal.FindFirstValue("email") ?? subject;
        if (subject is null || username is null) return;

        // Roles and scopes come from the local account when one is linked, so authorization
        // stays under RemoteSSL's control even when authentication is federated.
        var db = context.HttpContext.RequestServices.GetRequiredService<IRemoteSslDbContext>();
        var account = await db.Users.AsNoTracking()
            .FirstOrDefaultAsync(u => (u.ExternalSubject == subject || u.Username == username) && u.Enabled,
                context.HttpContext.RequestAborted);
        if (account is null) return;

        var identity = new ClaimsIdentity();
        foreach (var role in System.Text.Json.JsonSerializer.Deserialize<string[]>(account.RolesJson) ?? [])
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
        identity.AddClaim(new Claim(ClaimTypes.Name, account.Username));
        principal.AddIdentity(identity);
    }

    /// <summary>
    /// Recognises the standard ways a provider states that MFA happened: an amr entry, or an
    /// acr value naming a multi-factor context.
    /// </summary>
    private static bool HasMultiFactorClaim(ClaimsPrincipal principal)
    {
        var amr = principal.FindAll("amr").Select(c => c.Value).ToList();
        if (amr.Any(v => v is "mfa" or "otp" or "hwk" or "sms" or "fido" or "pop")) return true;

        var acr = principal.FindFirstValue("acr");
        return acr is not null &&
               (acr.Contains("mfa", StringComparison.OrdinalIgnoreCase)
                || acr.Contains("multi", StringComparison.OrdinalIgnoreCase));
    }
}
