using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Application.Certificates;
using RemoteSSL.Domain;

namespace RemoteSSL.Tests;

public class CertificateParserTests
{
    internal static X509Certificate2 CreateSelfSigned(
        string cn, DateTimeOffset notBefore, DateTimeOffset notAfter, params string[] dnsSans)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (dnsSans.Length > 0)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var dns in dnsSans) sanBuilder.AddDnsName(dns);
            request.CertificateExtensions.Add(sanBuilder.Build());
        }
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    [Fact]
    public void Parse_extracts_subject_issuer_validity_and_key_info()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(90);
        using var cert = CreateSelfSigned("test.example.com", notBefore, notAfter, "test.example.com", "alt.example.com");

        var parsed = CertificateParser.Parse(cert.RawData);

        Assert.Equal("test.example.com", parsed.CommonName);
        Assert.Contains("CN=test.example.com", parsed.SubjectDn);
        Assert.Equal(parsed.SubjectDn, parsed.IssuerDn); // self-signed
        Assert.Equal("RSA", parsed.PublicKeyAlgorithm);
        Assert.Equal(2048, parsed.KeySize);
        Assert.Equal(64, parsed.Sha256Thumbprint.Length);
        Assert.Equal(2, parsed.Sans.Count(s => s.Type == SanType.Dns));
        Assert.Contains(parsed.Sans, s => s.Value == "alt.example.com");
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", parsed.Pem);
        // X.509 stores validity with second precision
        Assert.Equal(notAfter.ToUnixTimeSeconds(), parsed.NotAfter.ToUnixTimeSeconds(), tolerance: 1);
    }

    [Fact]
    public void Parse_same_der_yields_same_thumbprint()
    {
        using var cert = CreateSelfSigned("dup.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var a = CertificateParser.Parse(cert.RawData);
        var b = CertificateParser.Parse(cert.RawData);
        Assert.Equal(a.Sha256Thumbprint, b.Sha256Thumbprint);
    }
}
