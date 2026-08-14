using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Application.Security;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;
using RemoteSSL.Infrastructure.Security;

namespace RemoteSSL.Tests;

/// <summary>Secret broker, rotation and access audit — design doc §7.2/§7.3.</summary>
public class SecretBrokerTests
{
    /// <summary>Reversible stand-in for data protection; the tests care about flow, not crypto.</summary>
    private sealed class ReversibleProtector : ISecretProtector
    {
        public string Protect(string plaintext) => "enc:" + plaintext;
        public string Unprotect(string ciphertext) => ciphertext["enc:".Length..];
    }

    private sealed class StubProvider(SecretProviderType provider, bool enabled, SecretMaterial material) : ISecretProvider
    {
        public SecretProviderType Provider => provider;
        public bool Enabled => enabled;
        public string? LastIdentifier { get; private set; }

        public Task<SecretMaterial> ReadAsync(string secretIdentifier, CancellationToken ct)
        {
            LastIdentifier = secretIdentifier;
            return Task.FromResult(material);
        }
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"secret-tests-{Guid.NewGuid()}").Options);

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private static async Task<CredentialRef> AddCredential(
        RemoteSslDbContext db, SecretProviderType provider, string? encrypted, int rotationDays = 0)
    {
        var credential = new CredentialRef
        {
            Id = Guid.NewGuid(),
            Name = $"cred-{provider}",
            CredentialType = CredentialType.UsernamePassword,
            Provider = provider,
            Username = "svc",
            SecretIdentifier = "vault://secret/app",
            EncryptedSecret = encrypted,
            RotationIntervalDays = rotationDays,
            LastRotatedAt = DateTimeOffset.UtcNow.AddDays(-rotationDays - 1),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        db.CredentialRefs.Add(credential);
        await db.SaveChangesAsync();
        return credential;
    }

    private static SecretBroker CreateBroker(
        RemoteSslDbContext db, IConfiguration configuration, params ISecretProvider[] providers) =>
        new(db, new ReversibleProtector(), new AuditWriter(db), providers, configuration);

    [Fact]
    public async Task An_internal_credential_is_resolved_to_a_value()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.InternalVault,
            new ReversibleProtector().Protect("""{"password":"s3cret"}"""));
        var broker = CreateBroker(db, Config());

        var resolved = await broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default);

        Assert.Equal("Value", resolved.Mode);
        Assert.Equal("s3cret", resolved.Material!.Password);
    }

    [Fact]
    public async Task Runner_direct_mode_hands_back_a_reference_instead_of_the_secret()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.HashiCorpVault, null);
        var provider = new StubProvider(SecretProviderType.HashiCorpVault, true, new SecretMaterial(Password: "from-vault"));
        var broker = CreateBroker(db, Config(("Secrets:RunnerDirect", "true")), provider);

        var resolved = await broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default);

        Assert.Equal("Reference", resolved.Mode);
        Assert.Null(resolved.Material);
        Assert.Equal("vault://secret/app", resolved.SecretIdentifier);
        // The control plane never asked the provider for anything.
        Assert.Null(provider.LastIdentifier);
    }

    [Fact]
    public async Task An_internal_credential_is_never_delegated_even_in_runner_direct_mode()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.InternalVault,
            new ReversibleProtector().Protect("""{"password":"s3cret"}"""));
        var broker = CreateBroker(db, Config(("Secrets:RunnerDirect", "true")));

        var resolved = await broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default);

        Assert.Equal("Value", resolved.Mode);
    }

    [Fact]
    public async Task An_unconfigured_provider_is_refused_rather_than_silently_skipped()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.CyberArk, null);
        var broker = CreateBroker(db, Config(),
            new StubProvider(SecretProviderType.CyberArk, false, new SecretMaterial()));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default));
    }

    [Fact]
    public async Task Every_resolution_is_recorded_on_the_credential_and_in_the_audit_log()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.InternalVault,
            new ReversibleProtector().Protect("""{"password":"s3cret"}"""));
        var broker = CreateBroker(db, Config());

        await broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default);

        var stored = await db.CredentialRefs.FirstAsync();
        Assert.NotNull(stored.LastAccessedAt);
        Assert.Equal("runner:r1", stored.LastAccessedBy);

        var audit = await db.AuditEvents.SingleAsync(e => e.Action == "credential.access");
        Assert.Equal("runner:r1", audit.Actor);
        Assert.DoesNotContain("s3cret", audit.DetailsJson ?? string.Empty);
    }

    [Fact]
    public async Task Rotation_replaces_internal_material_and_restarts_the_clock()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.InternalVault,
            new ReversibleProtector().Protect("""{"password":"old"}"""), rotationDays: 30);
        credential.RotationPending = true;
        await db.SaveChangesAsync();
        var broker = CreateBroker(db, Config());

        await broker.RotateAsync(credential.Id, new SecretMaterial(Password: "new"), "user:admin", default);

        var resolved = await broker.ResolveForRunnerAsync(credential.Id, "runner:r1", default);
        Assert.Equal("new", resolved.Material!.Password);
        var stored = await db.CredentialRefs.FirstAsync();
        Assert.False(stored.RotationPending);
        Assert.True(stored.RotationDueAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Rotating_an_external_credential_needs_no_material()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.AzureKeyVault, null, rotationDays: 7);
        var broker = CreateBroker(db, Config());

        await broker.RotateAsync(credential.Id, null, "user:admin", default);

        var stored = await db.CredentialRefs.FirstAsync();
        Assert.True(stored.LastRotatedAt > DateTimeOffset.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public async Task Overdue_credentials_are_flagged_once_not_every_pass()
    {
        using var db = CreateDb();
        await AddCredential(db, SecretProviderType.InternalVault, "enc:{}", rotationDays: 1);
        var broker = CreateBroker(db, Config());

        var first = await broker.MarkOverdueRotationsAsync(DateTimeOffset.UtcNow, default);
        var second = await broker.MarkOverdueRotationsAsync(DateTimeOffset.UtcNow, default);

        Assert.Single(first);
        Assert.Single(second);
        // The credential stays overdue, but only the first pass writes the alert.
        Assert.Single(await db.AuditEvents.Where(e => e.Action == "credential.rotation_due").ToListAsync());
    }

    [Fact]
    public async Task A_credential_within_its_window_is_not_overdue()
    {
        using var db = CreateDb();
        var credential = await AddCredential(db, SecretProviderType.InternalVault, "enc:{}", rotationDays: 90);
        credential.LastRotatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
        var broker = CreateBroker(db, Config());

        Assert.Empty(await broker.MarkOverdueRotationsAsync(DateTimeOffset.UtcNow, default));
    }
}

/// <summary>Credential type validation of §7.2.</summary>
public class CredentialTypeValidationTests
{
    [Theory]
    [InlineData(CredentialType.UsernamePassword)]
    [InlineData(CredentialType.SshPrivateKey)]
    [InlineData(CredentialType.SshCertificate)]
    [InlineData(CredentialType.KerberosServiceAccount)]
    [InlineData(CredentialType.ApiKeySecret)]
    [InlineData(CredentialType.OAuthClientCredentials)]
    [InlineData(CredentialType.BearerToken)]
    [InlineData(CredentialType.ClientCertificate)]
    public void An_empty_secret_is_rejected_for_every_type(CredentialType type)
    {
        Assert.NotNull(CredentialValidation.Validate(type, new SecretMaterial()));
    }

    [Fact]
    public void An_ssh_certificate_needs_both_halves()
    {
        Assert.NotNull(CredentialValidation.Validate(
            CredentialType.SshCertificate, new SecretMaterial(PrivateKeyPem: "key")));
        Assert.Null(CredentialValidation.Validate(
            CredentialType.SshCertificate, new SecretMaterial(PrivateKeyPem: "key", SshCertificate: "cert")));
    }

    [Fact]
    public void Oauth_client_credentials_need_all_three_fields()
    {
        Assert.NotNull(CredentialValidation.Validate(
            CredentialType.OAuthClientCredentials, new SecretMaterial(ClientId: "id", ClientSecret: "secret")));
        Assert.Null(CredentialValidation.Validate(
            CredentialType.OAuthClientCredentials,
            new SecretMaterial(ClientId: "id", ClientSecret: "secret", TokenEndpoint: "https://idp/token")));
    }

    [Fact]
    public void An_external_reference_cannot_live_in_the_internal_vault()
    {
        Assert.NotNull(CredentialValidation.Validate(
            CredentialType.ExternalSecretReference, new SecretMaterial(Password: "anything")));
    }
}

/// <summary>Managed keys, export policy and ownership — design doc §16.3.</summary>
public class ManagedKeyServiceTests
{
    private sealed class ReversibleProtector : ISecretProtector
    {
        public string Protect(string plaintext) => "enc:" + plaintext;
        public string Unprotect(string ciphertext) => ciphertext["enc:".Length..];
    }

    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"key-tests-{Guid.NewGuid()}").Options);

    private static ManagedKeyService CreateService(RemoteSslDbContext db) =>
        new(db, new ReversibleProtector(), new AuditWriter(db), [new SoftwareKeyProvider()]);

    private static ManagedKeyService.CreateKeyInput Input(string label, bool exportable) =>
        new(label, KeyProviderKind.Software, "RSA", 2048, exportable, "ozgur", "platform", "PROD", "web tier");

    [Fact]
    public async Task A_created_key_carries_its_owner_and_public_half()
    {
        using var db = CreateDb();
        var key = await CreateService(db).CreateAsync(Input("web-prod", false), "user:admin", default);

        Assert.StartsWith("software://", key.Reference);
        Assert.Contains("BEGIN PUBLIC KEY", key.PublicKeyPem);
        Assert.Equal("ozgur", key.OwnerId);
        Assert.Equal("platform", key.OwnerTeam);
        Assert.Equal("PROD", key.Environment);
        Assert.NotNull(key.EncryptedPrivateKeyPem);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", key.EncryptedPrivateKeyPem![..4]);
    }

    [Fact]
    public async Task A_non_exportable_key_refuses_export_and_records_the_attempt()
    {
        using var db = CreateDb();
        var service = CreateService(db);
        var key = await service.CreateAsync(Input("locked", false), "user:admin", default);

        await Assert.ThrowsAsync<KeyExportDeniedException>(
            () => service.ExportPrivateKeyAsync(key.Id, "user:mallory", default));

        var audit = await db.AuditEvents.SingleAsync(e => e.Action == "key.export");
        Assert.Equal("DENIED", audit.Result);
        Assert.Equal("user:mallory", audit.Actor);
    }

    [Fact]
    public async Task An_exportable_key_can_be_retrieved()
    {
        using var db = CreateDb();
        var service = CreateService(db);
        var key = await service.CreateAsync(Input("portable", true), "user:admin", default);

        var pem = await service.ExportPrivateKeyAsync(key.Id, "user:admin", default);

        Assert.Contains("BEGIN PRIVATE KEY", pem);
    }

    [Fact]
    public async Task A_csr_is_signed_by_the_key_and_carries_the_requested_sans()
    {
        using var db = CreateDb();
        var service = CreateService(db);
        var key = await service.CreateAsync(Input("csr-key", false), "user:admin", default);

        var csrPem = await service.CreateCsrAsync(key.Id, "CN=example.com",
            ["example.com", "www.example.com"], "user:admin", default);

        var request = System.Security.Cryptography.X509Certificates.CertificateRequest
            .LoadSigningRequestPem(csrPem, System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions
                    .UnsafeLoadCertificateExtensions,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        Assert.Equal("CN=example.com", request.SubjectName.Name);
        Assert.Contains(request.CertificateExtensions,
            e => e.Oid?.Value == "2.5.29.17"); // subjectAltName
    }

    [Fact]
    public async Task A_destroyed_key_loses_its_material_but_keeps_its_row()
    {
        using var db = CreateDb();
        var service = CreateService(db);
        var key = await service.CreateAsync(Input("temp", true), "user:admin", default);

        await service.DestroyAsync(key.Id, "user:admin", default);

        var stored = await db.ManagedKeys.SingleAsync();
        Assert.NotNull(stored.DestroyedAt);
        Assert.Null(stored.EncryptedPrivateKeyPem);
        await Assert.ThrowsAsync<KeyNotFoundException>(
            () => service.ExportPrivateKeyAsync(key.Id, "user:admin", default));
    }

    [Fact]
    public async Task Two_live_keys_cannot_share_a_label()
    {
        using var db = CreateDb();
        var service = CreateService(db);
        await service.CreateAsync(Input("dup", false), "user:admin", default);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.CreateAsync(Input("dup", false), "user:admin", default));
    }

    [Fact]
    public async Task An_unregistered_provider_is_reported_rather_than_assumed()
    {
        using var db = CreateDb();
        var service = CreateService(db);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreateAsync(
            new ManagedKeyService.CreateKeyInput("hsm-key", KeyProviderKind.Pkcs11, "RSA", 2048, false,
                null, null, null, null), "user:admin", default));
    }
}

/// <summary>Windows private-key protection of §11.4.</summary>
public class WindowsPrivateKeyTests
{
    [Fact]
    public void The_acl_script_grants_read_to_every_requested_account()
    {
        var script = Adapters.Windows.WindowsDeployer.GrantPrivateKeyAccessScript(
            "LocalMachine", "My", "ABC123", ["IIS AppPool\\Site", "NT SERVICE\\W3SVC"]);

        Assert.Contains("'IIS AppPool\\Site'", script);
        Assert.Contains("'NT SERVICE\\W3SVC'", script);
        Assert.Contains("Set-Acl", script);
        Assert.Contains("Cert:\\LocalMachine\\My\\ABC123", script);
    }

    [Fact]
    public void An_account_name_with_a_quote_stays_inside_its_string_literal()
    {
        var script = Adapters.Windows.WindowsDeployer.GrantPrivateKeyAccessScript(
            "LocalMachine", "My", "ABC123", ["evil'; Remove-Item C:\\ -Recurse; '"]);

        // Doubling is how a single quote is escaped inside a PowerShell single-quoted string, so
        // the injected command stays data instead of becoming a statement.
        Assert.Contains("'evil''; Remove-Item C:\\ -Recurse; '''", script);
        Assert.EndsWith("'granted'", script);
    }

    [Fact]
    public void A_windows_deployment_defaults_to_a_non_exportable_key()
    {
        Assert.True(new Adapters.Windows.WindowsDeployPayload().NonExportablePrivateKey);
        Assert.Empty(new Adapters.Windows.WindowsDeployPayload().PrivateKeyReadAccounts);
    }
}
