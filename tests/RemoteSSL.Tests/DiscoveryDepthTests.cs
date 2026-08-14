using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Application.Monitoring;

namespace RemoteSSL.Tests;

/// <summary>X.509 extension capture of design doc §6.2.</summary>
public class CertificateParserExtensionTests
{
    private const string OcspUrl = "http://ocsp.test/responder";
    private const string CaIssuerUrl = "http://ca.test/issuer.crt";
    private const string CrlUrl = "http://crl.test/list.crl";

    /// <summary>
    /// Hand-built AIA extension: .NET 8 has no builder for it, and the parser must read the
    /// real DER shape rather than something a helper normalised.
    /// </summary>
    private static X509Extension AuthorityInfoAccess(string caIssuerUrl, string ocspUrl)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var (method, url) in new[] { ("1.3.6.1.5.5.7.48.2", caIssuerUrl), ("1.3.6.1.5.5.7.48.1", ocspUrl) })
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(method);
                    writer.WriteCharacterString(System.Formats.Asn1.UniversalTagNumber.IA5String, url,
                        new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 6));
                }
            }
        }
        return new X509Extension("1.3.6.1.5.5.7.1.1", writer.Encode(), critical: false);
    }

    private static X509Certificate2 Build(Action<CertificateRequest> configure)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=fields.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        configure(request);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
    }

    [Fact]
    public void Basic_constraints_are_captured_for_a_ca_certificate()
    {
        using var cert = Build(r =>
            r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 2, true)));

        var parsed = CertificateParser.Parse(cert);
        Assert.True(parsed.IsCertificateAuthority);
        Assert.Equal(2, parsed.PathLengthConstraint);
    }

    [Fact]
    public void A_leaf_without_basic_constraints_is_not_reported_as_a_ca()
    {
        using var cert = Build(_ => { });
        var parsed = CertificateParser.Parse(cert);
        Assert.False(parsed.IsCertificateAuthority);
        Assert.Null(parsed.PathLengthConstraint);
    }

    [Fact]
    public void Key_usage_flags_are_listed_by_name()
    {
        using var cert = Build(r => r.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true)));

        var parsed = CertificateParser.Parse(cert);
        Assert.Contains("DigitalSignature", parsed.KeyUsages);
        Assert.Contains("KeyEncipherment", parsed.KeyUsages);
        Assert.DoesNotContain("KeyCertSign", parsed.KeyUsages);
    }

    [Fact]
    public void Extended_key_usages_are_resolved_to_readable_names()
    {
        using var cert = Build(r => r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], critical: false)));

        var parsed = CertificateParser.Parse(cert);
        var usage = Assert.Single(parsed.ExtendedKeyUsages);
        Assert.Contains("Server Authentication", usage);
    }

    [Fact]
    public void Aia_urls_are_split_into_ca_issuers_and_ocsp()
    {
        using var cert = Build(r => r.CertificateExtensions.Add(AuthorityInfoAccess(CaIssuerUrl, OcspUrl)));

        var parsed = CertificateParser.Parse(cert);
        Assert.Equal([CaIssuerUrl], parsed.CaIssuerUrls);
        Assert.Equal([OcspUrl], parsed.OcspUrls);
    }

    [Fact]
    public void Crl_distribution_points_are_captured()
    {
        using var cert = Build(r =>
            r.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUrl])));

        var parsed = CertificateParser.Parse(cert);
        Assert.Equal([CrlUrl], parsed.CrlDistributionPoints);
    }

    [Fact]
    public void A_certificate_without_those_extensions_yields_empty_lists_not_nulls()
    {
        using var cert = Build(_ => { });
        var parsed = CertificateParser.Parse(cert);
        Assert.Empty(parsed.KeyUsages);
        Assert.Empty(parsed.ExtendedKeyUsages);
        Assert.Empty(parsed.CaIssuerUrls);
        Assert.Empty(parsed.OcspUrls);
        Assert.Empty(parsed.CrlDistributionPoints);
    }
}

/// <summary>Application reachability rules of §2.1.</summary>
public class HealthCheckEvaluatorTests
{
    [Fact]
    public void Any_success_or_redirect_counts_when_no_status_is_configured()
    {
        Assert.Equal("Healthy", HealthCheckEvaluator.Evaluate(200, null, 12).Status);
        Assert.Equal("Healthy", HealthCheckEvaluator.Evaluate(302, null, 12).Status);
    }

    [Fact]
    public void Server_errors_are_unhealthy()
    {
        var result = HealthCheckEvaluator.Evaluate(500, null, 30);
        Assert.Equal("Unhealthy", result.Status);
        Assert.Contains("500", result.Detail);
    }

    [Fact]
    public void A_configured_status_must_match_exactly()
    {
        Assert.Equal("Healthy", HealthCheckEvaluator.Evaluate(204, 204, 5).Status);

        var mismatch = HealthCheckEvaluator.Evaluate(200, 204, 5);
        Assert.Equal("Unhealthy", mismatch.Status);
        Assert.Contains("expected 204", mismatch.Detail);
    }

    [Fact]
    public void Latency_is_reported_alongside_the_verdict()
    {
        Assert.Equal(42, HealthCheckEvaluator.Evaluate(200, null, 42).LatencyMs);
    }
}
