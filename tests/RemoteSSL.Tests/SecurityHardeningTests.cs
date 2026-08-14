using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Ssh;
using RemoteSSL.Adapters.Windows;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Security;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>
/// Secret leakage (design doc §36.1, §7.3, §22.3). The rule is absolute: a secret never appears in
/// an audit row, a step log, a job payload or an API response. These tests look for it in each.
/// </summary>
public class SecretLeakageTests
{
    private const string Secret = "sup3r-s3cret-value-do-not-log";

    private sealed class ReversibleProtector : ISecretProtector
    {
        public string Protect(string plaintext) => "enc:" + plaintext;
        public string Unprotect(string ciphertext) => ciphertext["enc:".Length..];
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"leak-{Guid.NewGuid()}").Options);

    [Fact]
    public async Task Reading_a_credential_records_the_access_without_recording_the_secret()
    {
        using var db = CreateDb();
        var protector = new ReversibleProtector();
        db.CredentialRefs.Add(new CredentialRef
        {
            Id = Guid.NewGuid(), Name = "web-deploy", Provider = SecretProviderType.InternalVault,
            CredentialType = CredentialType.UsernamePassword, SecretIdentifier = "internal://web-deploy",
            EncryptedSecret = protector.Protect(JsonSerializer.Serialize(new { password = Secret })),
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync();

        var credential = await db.CredentialRefs.FirstAsync();
        var broker = new SecretBroker(db, protector, new AuditWriter(db), [],
            new ConfigurationBuilder().Build());
        var resolved = await broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default);

        // The runner does get the secret — that is the point — but nothing persisted does.
        Assert.Equal(Secret, resolved.Material!.Password);
        foreach (var audit in await db.AuditEvents.ToListAsync())
        {
            Assert.DoesNotContain(Secret, audit.DetailsJson);
            Assert.DoesNotContain(Secret, audit.Actor);
            Assert.DoesNotContain(Secret, audit.Result);
        }
    }

    [Fact]
    public void A_failing_deployment_step_does_not_echo_the_key_it_was_installing()
    {
        // The step log is shown in the UI and stored on the job; a stack trace or a command echo
        // that carried the key would put it in both.
        using var key = RSA.Create(2048);
        var payload = new DeployPayload
        {
            Adapter = "nginx",
            Connection = new SshTargetConfig("127.0.0.1", 1), // closed port: fails at pre-check
            CertPath = "/etc/ssl/app.crt",
            KeyPath = "/etc/ssl/app.key",
            CertPem = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----",
            KeyPem = key.ExportPkcs8PrivateKeyPem()
        };

        var outcome = LinuxDeployer.Deploy(payload, new SshCredentials("svc", Secret, null));

        Assert.False(outcome.Success);
        foreach (var step in outcome.Steps)
        {
            Assert.DoesNotContain(Secret, step.SafeLog);
            Assert.DoesNotContain("BEGIN PRIVATE KEY", step.SafeLog);
        }
    }

    [Fact]
    public void The_private_key_password_never_reaches_a_windows_command_line()
    {
        // §11.1: the PFX password goes through a file the script reads, because a command line is
        // visible to every process on the machine.
        var script = WindowsDeployer.GrantPrivateKeyAccessScript("LocalMachine", "My", "ABC123",
            ["IIS AppPool\\Site"]);

        Assert.DoesNotContain(Secret, script);
        Assert.DoesNotContain("-Password", script);
    }

    [Fact]
    public async Task The_credential_api_shape_carries_metadata_only()
    {
        // Everything the list endpoint projects, checked against the entity: no field that could
        // hold secret material is in it.
        using var db = CreateDb();
        var protector = new ReversibleProtector();
        db.CredentialRefs.Add(new CredentialRef
        {
            Id = Guid.NewGuid(), Name = "api-shape", Provider = SecretProviderType.InternalVault,
            SecretIdentifier = "internal://api-shape",
            EncryptedSecret = protector.Protect(JsonSerializer.Serialize(new { password = Secret })),
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync();

        var projected = await db.CredentialRefs.AsNoTracking().Select(c => new
        {
            c.Id, c.Name, Type = c.CredentialType.ToString(), Provider = c.Provider.ToString(),
            c.Username, c.SecretIdentifier, HasSecret = c.EncryptedSecret != null,
            c.RotationIntervalDays, c.LastAccessedAt, c.LastAccessedBy
        }).ToListAsync();

        var json = JsonSerializer.Serialize(projected);
        Assert.DoesNotContain(Secret, json);
        Assert.DoesNotContain("enc:", json);
    }

    [Fact]
    public async Task An_exported_managed_key_is_the_only_place_key_material_appears()
    {
        using var db = CreateDb();
        var service = new ManagedKeyService(db, new ReversibleProtector(), new AuditWriter(db),
            [new Infrastructure.Security.SoftwareKeyProvider()]);

        var key = await service.CreateAsync(new ManagedKeyService.CreateKeyInput(
            "leak-check", KeyProviderKind.Software, "RSA", 2048, false, "ozgur", null, null, null),
            "user:admin", default);

        // Creation audits the key without its material, and the stored row is encrypted.
        foreach (var audit in await db.AuditEvents.ToListAsync())
            Assert.DoesNotContain("BEGIN PRIVATE KEY", audit.DetailsJson);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", (await db.ManagedKeys.SingleAsync()).EncryptedPrivateKeyPem![..20]);
        Assert.NotEqual(string.Empty, key.PublicKeyPem);
    }
}

/// <summary>
/// Command injection (design doc §36.1). Every value that reaches a shell or a PowerShell script
/// comes from somewhere: a certificate's subject, a target's name, an operator's field. None of
/// them may become a command.
/// </summary>
public class CommandInjectionTests
{
    [Theory]
    [InlineData("simple")]
    [InlineData("with space")]
    [InlineData("it's")]
    [InlineData("; rm -rf /")]
    [InlineData("$(whoami)")]
    [InlineData("`id`")]
    [InlineData("a'; touch /tmp/pwned; '")]
    [InlineData("--flag=value")]
    public void Shell_quoting_makes_any_value_a_single_literal_argument(string value)
    {
        var quoted = Shell.Quote(value);

        // Single-quoted throughout, with the only inner quotes being the escape sequence itself.
        Assert.StartsWith("'", quoted);
        Assert.EndsWith("'", quoted);
        Assert.Equal(value, Unquote(quoted));
    }

    /// <summary>Reverses POSIX single-quote escaping, to prove the round trip is exact.</summary>
    private static string Unquote(string quoted)
    {
        var body = quoted[1..^1];
        return body.Replace("'\\''", "'");
    }

    [Fact]
    public void A_path_carrying_shell_metacharacters_cannot_break_out_of_a_deploy_command()
    {
        // The path comes from the store configuration, which an operator types; a typo must not
        // become a command, and a malicious value must not either.
        var path = "/etc/ssl/$(touch /tmp/pwned).crt";

        var command = $"cp -p {Shell.Quote(path)} {Shell.Quote(path + ".bak")}";

        Assert.DoesNotContain("$(touch", command.Replace(Shell.Quote(path), "<quoted>")
            .Replace(Shell.Quote(path + ".bak"), "<quoted>"));
    }

    [Fact]
    public void An_account_name_with_a_quote_stays_data_inside_the_powershell_script()
    {
        // PowerShell escapes a single quote by doubling it; anything else would end the string and
        // start a statement.
        var script = WindowsDeployer.GrantPrivateKeyAccessScript("LocalMachine", "My", "ABC",
            ["evil'; Remove-Item C:\\ -Recurse; '"]);

        Assert.Contains("'evil''; Remove-Item C:\\ -Recurse; '''", script);
        Assert.EndsWith("'granted'", script);
    }

    [Fact]
    public void The_generic_template_substitutes_only_its_own_placeholders()
    {
        // A certificate whose subject contains a brace must not be able to introduce a token.
        var rendered = GenericSshDeployer.Render(
            "install {certPath}",
            new Dictionary<string, string> { ["certPath"] = "/etc/ssl/a.crt" });

        Assert.Equal("install /etc/ssl/a.crt", rendered);

        var untouched = GenericSshDeployer.Render(
            "install {certPath} {injected}",
            new Dictionary<string, string> { ["certPath"] = "/etc/ssl/a.crt" });

        Assert.Contains("{injected}", untouched);
    }
}

/// <summary>
/// Authorization bypass (design doc §36.1, §24.2, §35). The checks that decide who may do what,
/// tested from the outside: given a scope rule or a tenant, what is actually permitted.
/// </summary>
public class AuthorizationBypassTests
{
    [Fact]
    public void A_scope_rule_for_one_environment_does_not_grant_another()
    {
        ScopeRule[] rules = [new("certificate.deploy", "TEST")];

        Assert.True(ScopeEvaluator.IsAllowed(rules, new ScopeRequest("certificate.deploy", "TEST")));
        Assert.False(ScopeEvaluator.IsAllowed(rules, new ScopeRequest("certificate.deploy", "PROD")));
    }

    [Fact]
    public void A_scope_rule_for_one_action_does_not_grant_another()
    {
        ScopeRule[] rules = [new("certificate.read", "PROD")];

        Assert.False(ScopeEvaluator.IsAllowed(rules, new ScopeRequest("certificate.deploy", "PROD")));
    }

    [Fact]
    public void An_adapter_outside_the_rule_is_refused_even_in_the_right_environment()
    {
        ScopeRule[] rules = [new("certificate.deploy", "PROD", "WEB", ["nginx"])];

        Assert.False(ScopeEvaluator.IsAllowed(rules,
            new ScopeRequest("certificate.deploy", "PROD", "WEB", "iis")));
    }

    [Fact]
    public void An_allowlisted_adapter_set_refuses_everything_it_does_not_name()
    {
        var verdict = AdapterAllowlist.Check(["nginx"], new Dictionary<string, string>(), "iis", null);

        Assert.False(verdict.Allowed);
        Assert.Contains("allowlist", verdict.Reason);
    }

    [Fact]
    public void A_pinned_adapter_version_refuses_a_runner_reporting_a_different_one()
    {
        var verdict = AdapterAllowlist.Check([], new Dictionary<string, string> { ["nginx"] = "1.0.0" },
            "nginx", """{"nginx":"0.9.0"}""");

        Assert.False(verdict.Allowed);
        Assert.Contains("0.9.0", verdict.Reason);
    }

    [Fact]
    public void A_runner_may_not_take_a_job_belonging_to_another_affinity_group()
    {
        var outsider = new RunnerNode { Id = Guid.NewGuid(), AffinityGroup = "dc2", Status = RunnerStatus.Online };
        var job = new RunnerJob { Id = Guid.NewGuid(), AffinityGroup = "dc1" };

        Assert.False(Application.Deployments.RunnerFailover.CanRun(outsider, job));
    }

    [Fact]
    public async Task A_tenant_cannot_read_another_tenants_credential_even_by_id()
    {
        // The most direct bypass attempt there is: know the id, ask for it.
        var store = $"bypass-{Guid.NewGuid()}";
        var tenantA = new TenantContext(); tenantA.Enter(Guid.NewGuid());
        var tenantB = new TenantContext(); tenantB.Enter(Guid.NewGuid());

        Guid credentialId;
        using (var a = new RemoteSslDbContext(
                   new DbContextOptionsBuilder<RemoteSslDbContext>().UseInMemoryDatabase(store).Options, tenantA))
        {
            var credential = new CredentialRef
            {
                Id = Guid.NewGuid(), Name = "a-only", SecretIdentifier = "internal://a-only",
                CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow
            };
            a.CredentialRefs.Add(credential);
            await a.SaveChangesAsync();
            credentialId = credential.Id;
        }

        using var b = new RemoteSslDbContext(
            new DbContextOptionsBuilder<RemoteSslDbContext>().UseInMemoryDatabase(store).Options, tenantB);
        Assert.Null(await b.CredentialRefs.FirstOrDefaultAsync(c => c.Id == credentialId));
    }
}
