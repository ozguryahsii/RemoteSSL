using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Application.Requests;
using RemoteSSL.Domain.Abstractions;
using RemoteSSL.Infrastructure.Ca;

namespace RemoteSSL.Tests;

/// <summary>ACME protocol details — design doc §18.3, RFC 8555.</summary>
public class AcmeConnectorTests
{
    private static AcmeConnector Connector(string? challengeType = null) =>
        new(new AcmeConfig
        {
            DirectoryUrl = "https://acme.test/directory",
            ChallengeType = challengeType ?? "dns-01",
            AccountKeyPem = TestKeyPem
        });

    /// <summary>A fixed account key, so the thumbprint-derived values below are reproducible.</summary>
    private static readonly string TestKeyPem = CreateKeyPem();

    private static string CreateKeyPem()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return key.ExportPkcs8PrivateKeyPem();
    }

    [Fact]
    public void The_key_authorization_is_the_token_joined_to_the_account_key_thumbprint()
    {
        var connector = Connector();

        var authorization = connector.KeyAuthorization("tok123");

        Assert.StartsWith("tok123.", authorization);
        // The thumbprint half is a base64url SHA-256: 43 characters, no padding, no + or /.
        var thumbprint = authorization["tok123.".Length..];
        Assert.Equal(43, thumbprint.Length);
        Assert.DoesNotContain('=', thumbprint);
        Assert.DoesNotContain('+', thumbprint);
        Assert.DoesNotContain('/', thumbprint);
    }

    [Fact]
    public void The_same_account_key_always_produces_the_same_key_authorization()
    {
        // Two connectors over one key must agree, or a challenge answered by one would fail for
        // the other after a restart.
        Assert.Equal(Connector().KeyAuthorization("tok"), Connector().KeyAuthorization("tok"));
    }

    [Fact]
    public void A_different_account_key_produces_a_different_key_authorization()
    {
        var other = new AcmeConnector(new AcmeConfig { AccountKeyPem = CreateKeyPem() });

        Assert.NotEqual(Connector().KeyAuthorization("tok"), other.KeyAuthorization("tok"));
    }

    [Fact]
    public void The_dns_record_value_is_the_hash_of_the_key_authorization_not_the_token()
    {
        var connector = Connector();

        var record = connector.DnsRecordValue("tok123");

        Assert.Equal(43, record.Length);
        Assert.NotEqual(connector.KeyAuthorization("tok123"), record);
    }

    [Fact]
    public void An_account_key_is_generated_when_none_is_configured()
    {
        var connector = new AcmeConnector(new AcmeConfig());

        Assert.Contains("BEGIN PRIVATE KEY", connector.AccountKeyPem);
    }

    [Fact]
    public async Task Only_the_dns_challenge_profile_allows_wildcards()
    {
        var profiles = await Connector().ListProfilesAsync(default);

        Assert.True(profiles.Single(p => p.ProfileId == "dns-01").SupportsWildcard);
        Assert.False(profiles.Single(p => p.ProfileId == "http-01").SupportsWildcard);
    }

    [Fact]
    public void The_names_to_order_come_from_the_csr_subject_and_its_sans()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=app.example.com", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var sans = new SubjectAlternativeNameBuilder();
        sans.AddDnsName("app.example.com");
        sans.AddDnsName("www.example.com");
        request.CertificateExtensions.Add(sans.Build());

        var names = AcmeConnector.NamesFromCsr(request.CreateSigningRequestPem());

        Assert.Equal(2, names.Count);
        Assert.Contains("app.example.com", names);
        Assert.Contains("www.example.com", names);
    }

    [Fact]
    public void A_pem_bundle_is_split_into_the_leaf_and_the_chain_behind_it()
    {
        var leaf = SelfSigned("CN=leaf.example.com");
        var intermediate = SelfSigned("CN=Intermediate CA");

        var issued = AcmeConnector.SplitBundle(leaf + "\n" + intermediate);

        Assert.Contains("BEGIN CERTIFICATE", issued.LeafPem);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(issued.LeafPem, "BEGIN CERTIFICATE"));
        Assert.Contains("BEGIN CERTIFICATE", issued.ChainPem);
        Assert.NotEmpty(issued.SerialNumber);
    }

    [Fact]
    public void A_response_with_no_certificate_is_reported_rather_than_returning_an_empty_one()
    {
        Assert.Throws<InvalidOperationException>(() => AcmeConnector.SplitBundle("not a certificate"));
    }

    [Fact]
    public void Revocation_reasons_map_to_the_rfc_5280_codes_acme_expects()
    {
        Assert.Equal(1, AcmeConnector.ToAcmeReason(RevocationReason.KeyCompromise));
        Assert.Equal(4, AcmeConnector.ToAcmeReason(RevocationReason.Superseded));
        Assert.Equal(5, AcmeConnector.ToAcmeReason(RevocationReason.CessationOfOperation));
        Assert.Equal(0, AcmeConnector.ToAcmeReason(RevocationReason.Unspecified));
    }

    [Fact]
    public async Task Revoking_by_serial_alone_is_refused_because_acme_needs_the_certificate()
    {
        await Assert.ThrowsAsync<NotSupportedException>(
            () => Connector().RevokeAsync("0a1b", RevocationReason.Superseded, default));
    }

    private static string SelfSigned(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        return certificate.ExportCertificatePem();
    }
}

/// <summary>AD CS certsrv responses — design doc §18.3.</summary>
public class AdcsConnectorTests
{
    [Fact]
    public void The_request_id_is_read_from_the_retrieval_link()
    {
        const string html = """
            <html><body>Certificate Issued
            <A HREF="certnew.cer?ReqID=4271&amp;Enc=b64">Download certificate</A>
            </body></html>
            """;

        Assert.Equal("4271", AdcsConnector.ExtractRequestId(html));
    }

    [Fact]
    public void A_pending_request_still_yields_its_id_from_the_status_page_link()
    {
        const string html = """<A HREF="certckpn.asp?ReqID=99">check status</A>""";

        Assert.Equal("99", AdcsConnector.ExtractRequestId(html));
    }

    [Fact]
    public void A_page_with_no_request_id_returns_null_rather_than_a_wrong_one()
    {
        Assert.Null(AdcsConnector.ExtractRequestId("<html><body>Nothing here</body></html>"));
    }

    [Fact]
    public void A_denied_request_reports_the_policy_module_reason()
    {
        const string html = "<html>Denied by Policy Module 0x80094800, The request template is not supported</html>";

        Assert.Contains("Denied by Policy Module", AdcsConnector.DenialReason(html));
    }

    [Fact]
    public void A_request_awaiting_approval_says_so_instead_of_looking_like_a_failure()
    {
        const string html = "<html>Your certificate request has been received and taken under submission</html>";

        Assert.Contains("pending a certificate manager", AdcsConnector.DenialReason(html));
    }

    [Fact]
    public async Task Templates_from_configuration_become_the_profile_list()
    {
        var connector = new AdcsConnector(new AdcsConfig
        {
            BaseUrl = "https://ca.test",
            Templates = ["WebServer", "WebServerV2"]
        });

        var profiles = await connector.ListProfilesAsync(default);

        Assert.Equal(2, profiles.Count);
        Assert.Contains(profiles, p => p.ProfileId == "WebServerV2");
    }

    [Fact]
    public async Task Revocation_is_refused_with_an_explanation_rather_than_failing_obscurely()
    {
        var connector = new AdcsConnector(new AdcsConfig { BaseUrl = "https://ca.test" });

        var error = await Assert.ThrowsAsync<NotSupportedException>(
            () => connector.RevokeAsync("0a1b", RevocationReason.Superseded, default));
        Assert.Contains("certutil", error.Message);
    }
}

/// <summary>The generic REST CA presets — design doc §18.3.</summary>
public class GenericRestCaTests
{
    [Fact]
    public void The_sectigo_preset_names_its_own_id_and_status_fields()
    {
        var preset = GenericRestCaConfig.Sectigo();

        Assert.Equal("sectigo", preset.ConnectorType);
        Assert.Equal("sslId", preset.RequestIdField);
        Assert.Contains("issued", preset.IssuedValues);
        Assert.Contains("revoked", preset.RejectedValues);
    }

    [Fact]
    public async Task Configured_profiles_are_offered_when_the_api_cannot_enumerate_them()
    {
        var connector = new GenericRestCaConnector(
            new RestCaConfig { BaseUrl = "https://ca.test", Profiles = ["ov-ssl", "ev-ssl"] },
            new GenericRestCaConfig());

        var profiles = await connector.ListProfilesAsync(default);

        Assert.Equal(2, profiles.Count);
        Assert.Contains(profiles, p => p.ProfileId == "ev-ssl");
    }

    [Fact]
    public void Every_supported_connector_type_can_be_created_by_the_factory()
    {
        // The list is what the CA integrations screen offers; a type on it that the factory
        // cannot build would fail only when someone tried to use it.
        Assert.Contains("acme", CaConnectorFactory.SupportedTypes);
        Assert.Contains("adcs", CaConnectorFactory.SupportedTypes);
        Assert.Contains("digicert", CaConnectorFactory.SupportedTypes);
        Assert.Contains("sectigo", CaConnectorFactory.SupportedTypes);
        Assert.Contains("rest-ca", CaConnectorFactory.SupportedTypes);
    }
}

/// <summary>CA webhook handling — ADR-009.</summary>
public class CaWebhookTests
{
    [Theory]
    [InlineData("""{"requestId":"4271"}""", "4271")]
    [InlineData("""{"order_id":"ord_9"}""", "ord_9")]
    [InlineData("""{"sslId":12345}""", "12345")]
    public void The_provider_request_id_is_found_under_whichever_name_the_ca_uses(string body, string expected)
    {
        Assert.Equal(expected, CaCallback.ExtractProviderRequestId(body));
    }

    [Fact]
    public void A_callback_with_no_recognisable_id_widens_the_recheck_instead_of_failing()
    {
        Assert.Null(CaCallback.ExtractProviderRequestId("""{"event":"issued"}"""));
        Assert.Null(CaCallback.ExtractProviderRequestId("not json at all"));
        Assert.Null(CaCallback.ExtractProviderRequestId(""));
    }
}
