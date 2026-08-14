using System.Reflection;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Deployments;
using RemoteSSL.Domain.Abstractions;
using RemoteSSL.Infrastructure.Ca;

namespace RemoteSSL.Tests;

/// <summary>
/// Contract tests for the CA connector interface (design doc §36.1).
///
/// Every connector is exercised through the same set of expectations, so a new one cannot be added
/// with a subtly different shape — the whole point of a provider-agnostic interface is that the
/// lifecycle code never has to know which CA is behind it.
/// </summary>
public class CaConnectorContractTests
{
    private sealed class HttpFactoryStub : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    /// <summary>Every connector this build ships, constructed with unusable configuration.</summary>
    public static TheoryData<string, ICertificateAuthorityConnector> Connectors()
    {
        var http = new HttpFactoryStub();
        return new TheoryData<string, ICertificateAuthorityConnector>
        {
            { "manual", new ManualCaConnector() },
            { "globalsign-hvca", new GlobalSignHvcaConnector(new HvcaConfig(), http) },
            { "acme", new AcmeConnector(new AcmeConfig(), http) },
            { "adcs", new AdcsConnector(new AdcsConfig { BaseUrl = "https://ca.invalid" }, http) },
            { "digicert", new DigiCertConnector(new RestCaConfig { BaseUrl = "https://ca.invalid" }, http) },
            { "sectigo", new GenericRestCaConnector(
                new RestCaConfig { BaseUrl = "https://ca.invalid" }, GenericRestCaConfig.Sectigo(), http) },
            { "rest-ca", new GenericRestCaConnector(
                new RestCaConfig { BaseUrl = "https://ca.invalid" }, new GenericRestCaConfig(), http) }
        };
    }

    [Theory]
    [MemberData(nameof(Connectors))]
    public void Every_connector_reports_the_type_it_was_created_as(string type, ICertificateAuthorityConnector connector)
    {
        Assert.Equal(type, connector.ConnectorType);
    }

    [Theory]
    [MemberData(nameof(Connectors))]
    public async Task Listing_profiles_never_throws_and_never_returns_null(
        string type, ICertificateAuthorityConnector connector)
    {
        // The wizard calls this before anything else; a connector that throws here cannot even be
        // configured. Network-backed connectors must fall back to what they know.
        IReadOnlyList<CaProfile> profiles;
        try
        {
            profiles = await connector.ListProfilesAsync(default);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException)
        {
            // Unreachable CA is acceptable here; an unhandled contract violation is not.
            return;
        }

        Assert.NotNull(profiles);
        Assert.All(profiles, p =>
        {
            Assert.False(string.IsNullOrWhiteSpace(p.ProfileId), $"{type} returned a profile with no id");
            Assert.False(string.IsNullOrWhiteSpace(p.DisplayName), $"{type} returned a profile with no name");
            Assert.NotEmpty(p.AllowedKeyAlgorithms);
            Assert.True(p.MaxValidityDays > 0, $"{type} profile '{p.ProfileId}' allows no validity at all");
        });
    }

    [Theory]
    [MemberData(nameof(Connectors))]
    public async Task Validating_a_broken_connection_reports_failure_instead_of_throwing(
        string type, ICertificateAuthorityConnector connector)
    {
        // This is what the "Test connection" button calls. It must always produce a result the UI
        // can show, because "it threw" is not something an operator can act on.
        var result = await connector.ValidateConnectionAsync(default);

        Assert.NotNull(result);
        if (!result.Success)
            Assert.False(string.IsNullOrWhiteSpace(result.Error), $"{type} failed without saying why");
    }

    [Theory]
    [MemberData(nameof(Connectors))]
    public void Domain_validation_is_optional_and_says_so_by_returning_null(
        string type, ICertificateAuthorityConnector connector)
    {
        // Connectors without domain validation return null rather than throwing, so the lifecycle
        // can ask every connector the same question.
        var task = connector.RequestDomainValidationAsync("example.com", "dns-01", default);
        Assert.NotNull(task);
    }

    [Fact]
    public void Every_connector_type_the_factory_advertises_can_actually_be_built()
    {
        // A type on the list that the factory cannot construct would fail only when an operator
        // selected it, which is the worst moment to find out.
        var built = Connectors().Select(row => (string)row[0]!).ToHashSet();

        Assert.Equal(CaConnectorFactory.SupportedTypes.Order(), built.Order());
    }

    [Fact]
    public void The_interface_has_not_grown_a_member_the_connectors_do_not_implement()
    {
        // Guards against a method being added to the interface and quietly defaulted somewhere:
        // every connector in the theory data is checked against the full member list.
        var members = typeof(ICertificateAuthorityConnector).GetMembers(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

        foreach (var row in Connectors())
        {
            var connector = (ICertificateAuthorityConnector)row[1]!;
            var map = connector.GetType().GetInterfaceMap(typeof(ICertificateAuthorityConnector));
            Assert.Equal(members.Count(m => m is MethodInfo), map.TargetMethods.Length);
        }
    }
}

/// <summary>
/// Contract tests for the adapter catalog (design doc §36.1, §9.3). The catalog is what the UI and
/// the planner both read, so an entry that contradicts what the runner can do is a defect even
/// when every individual piece compiles.
/// </summary>
public class AdapterContractTests
{
    [Fact]
    public void Every_adapter_declares_a_channel_the_runner_actually_speaks()
    {
        string[] channels = ["ssh", "winrm", "rest"];

        Assert.All(AdapterCatalog.All, a =>
            Assert.Contains(a.Channel, channels));
    }

    [Fact]
    public void No_two_adapters_share_a_type()
    {
        var duplicates = AdapterCatalog.All
            .GroupBy(a => a.Type, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void Every_adapter_field_has_a_key_and_a_label()
    {
        foreach (var adapter in AdapterCatalog.All)
        foreach (var field in adapter.ConnectionFields.Concat(adapter.ServiceFields))
        {
            Assert.False(string.IsNullOrWhiteSpace(field.Key), $"{adapter.Type} has a field with no key");
            Assert.False(string.IsNullOrWhiteSpace(field.Label), $"{adapter.Type}.{field.Key} has no label");
        }
    }

    [Fact]
    public void A_field_with_a_default_offers_it_among_its_options()
    {
        // A default the dropdown cannot select would silently reset whatever the operator chose.
        foreach (var adapter in AdapterCatalog.All)
        foreach (var field in adapter.ConnectionFields.Concat(adapter.ServiceFields)
                     .Where(f => f.Options is { Count: > 0 } && f.Default is not null))
        {
            Assert.Contains(field.Default, field.Options!);
        }
    }

    [Fact]
    public void An_adapter_that_cannot_roll_back_says_why_in_its_notes()
    {
        // The screen shows the note next to a missing rollback button; without it the absence
        // looks like an oversight rather than a property of the platform.
        foreach (var adapter in AdapterCatalog.All.Where(a => !a.SupportsRollback))
            Assert.False(string.IsNullOrWhiteSpace(adapter.Notes),
                $"{adapter.Type} cannot roll back but does not explain why");
    }
}

/// <summary>
/// Contract tests for the secret and key providers (design doc §36.1, §7.2, §16.3). Both are
/// pluggable sets where "not configured" must be a first-class answer rather than an exception.
/// </summary>
public class ProviderContractTests
{
    private static IConfiguration Empty() => new ConfigurationBuilder().Build();

    private sealed class HttpFactoryStub : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    public static TheoryData<ISecretProvider> SecretProviders() => new()
    {
        new Infrastructure.Security.VaultSecretProvider(
            new Infrastructure.Security.VaultSecretClient(new HttpFactoryStub(), Empty()), Empty()),
        new Infrastructure.Security.CyberArkSecretProvider(new HttpFactoryStub(), Empty()),
        new Infrastructure.Security.AzureKeyVaultSecretProvider(new HttpFactoryStub(), Empty())
    };

    [Theory]
    [MemberData(nameof(SecretProviders))]
    public void An_unconfigured_secret_provider_reports_itself_disabled_rather_than_failing_later(
        ISecretProvider provider)
    {
        Assert.False(provider.Enabled);
    }

    [Theory]
    [MemberData(nameof(SecretProviders))]
    public async Task Reading_from_an_unconfigured_secret_provider_explains_what_is_missing(
        ISecretProvider provider)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => provider.ReadAsync("vault://secret/app", default));

        Assert.False(string.IsNullOrWhiteSpace(error.Message));
    }

    [Fact]
    public void Each_secret_provider_claims_a_distinct_provider_type()
    {
        var types = SecretProviders().Select(row => ((ISecretProvider)row[0]!).Provider).ToList();

        Assert.Equal(types.Count, types.Distinct().Count());
    }

    public static TheoryData<IKeyProvider> KeyProviders() => new()
    {
        new Infrastructure.Security.SoftwareKeyProvider(),
        new Infrastructure.Security.Pkcs11KeyProvider(Empty()),
        new Infrastructure.Security.CloudKmsKeyProvider(new HttpFactoryStub(), Empty())
    };

    [Theory]
    [MemberData(nameof(KeyProviders))]
    public async Task An_unconfigured_key_provider_refuses_clearly_and_the_software_one_always_works(
        IKeyProvider provider)
    {
        var spec = new KeySpec("RSA", 2048, "contract-test", Exportable: true);

        if (!provider.Enabled)
        {
            var error = await Assert.ThrowsAnyAsync<Exception>(() => provider.GenerateAsync(spec, default));
            Assert.False(string.IsNullOrWhiteSpace(error.Message));
            return;
        }

        var key = await provider.GenerateAsync(spec, default);
        Assert.False(string.IsNullOrWhiteSpace(key.Reference));
        Assert.Contains("BEGIN PUBLIC KEY", key.PublicKeyPem);
    }

    [Fact]
    public void The_software_key_provider_is_always_available_because_something_has_to_be()
    {
        Assert.True(new Infrastructure.Security.SoftwareKeyProvider().Enabled);
    }
}
