using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Application.Automation;
using RemoteSSL.Application.Certificates;

namespace RemoteSSL.Tests;

public class CertificateFactoryTests
{
    [Theory]
    [InlineData("RSA", 2048)]
    [InlineData("RSA", 4096)]
    [InlineData("EC", 256)]
    [InlineData("EC", 384)]
    public void GenerateCsr_produces_valid_pem_pair(string alg, int size)
    {
        var r = CertificateFactory.GenerateCsr("app.example.com", ["app.example.com", "www.example.com"], alg, size);
        Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", r.CsrPem);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", r.PrivateKeyPem);
    }

    [Fact]
    public void GenerateCsr_includes_full_subject_dn()
    {
        var r = CertificateFactory.GenerateCsr("app.ozgur.com.tr", [], "RSA", 2048,
            new CertificateFactory.SubjectOptions("Vienna Life", "IT", "Istanbul", "Istanbul", "tr"));
        var req = System.Security.Cryptography.X509Certificates.CertificateRequest.LoadSigningRequestPem(
            r.CsrPem, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions.SkipSignatureValidation);
        var dn = req.SubjectName.Name;
        Assert.Contains("CN=app.ozgur.com.tr", dn);
        Assert.Contains("O=Vienna Life", dn);
        Assert.Contains("OU=IT", dn);
        Assert.Contains("L=Istanbul", dn);
        Assert.Contains("C=TR", dn);
    }

    [Fact]
    public void GenerateCsr_rejects_weak_rsa()
        => Assert.Throws<ArgumentException>(() => CertificateFactory.GenerateCsr("x", [], "RSA", 1024));

    [Fact]
    public void Pfx_roundtrip_preserves_leaf_and_key()
    {
        using var cert = CertificateParserTests.CreateSelfSigned("pfx.example.com",
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var certPem = cert.ExportCertificatePem();
        var keyPem = cert.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();

        var pfx = CertificateFactory.BuildPfx(certPem, keyPem, null, "test-pass");
        var parsed = CertificateFactory.ParsePfx(pfx, "test-pass");

        using var back = X509Certificate2.CreateFromPem(parsed.LeafPem);
        Assert.Equal(cert.Thumbprint, back.Thumbprint);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", parsed.PrivateKeyPem);
    }

    [Fact]
    public void BuildOrderedChain_orders_intermediates_and_excludes_root()
    {
        using var rootKey = System.Security.Cryptography.RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test Root", rootKey,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddYears(10));

        using var interKey = System.Security.Cryptography.RSA.Create(2048);
        var interReq = new CertificateRequest("CN=Test Intermediate", interKey,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        interReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var inter = interReq.Create(root, DateTimeOffset.UtcNow.AddDays(-5), DateTimeOffset.UtcNow.AddYears(5), [1]);

        using var leafKey = System.Security.Cryptography.RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=leaf.example.com", leafKey,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var interWithKey = inter.CopyWithPrivateKey(interKey);
        using var leaf = leafReq.Create(interWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [2]);

        // pool intentionally unordered: root first
        var pool = root.ExportCertificatePem() + "\n" + inter.ExportCertificatePem();
        var chain = CertificateFactory.BuildOrderedChain(leaf.ExportCertificatePem(), pool);

        var chainCerts = CertificateFactory.ParsePemCertificates(chain).ToList();
        Assert.Single(chainCerts); // root excluded
        Assert.Equal("CN=Test Intermediate", chainCerts[0].Subject);
        Assert.True(CertificateFactory.ValidateChainOrder(leaf.ExportCertificatePem(), chain));
    }

    [Theory]
    [InlineData("""{"days":["SUN"],"start":"01:00","end":"04:00"}""", "2026-08-16T02:00:00Z", true)]  // Sunday 02:00
    [InlineData("""{"days":["SUN"],"start":"01:00","end":"04:00"}""", "2026-08-16T05:00:00Z", false)] // Sunday 05:00
    [InlineData("""{"days":["SUN"],"start":"01:00","end":"04:00"}""", "2026-08-17T02:00:00Z", false)] // Monday
    [InlineData("""{"start":"22:00","end":"02:00"}""", "2026-08-13T23:00:00Z", true)]                 // overnight window
    [InlineData("not json", "2026-08-13T12:00:00Z", true)]                                            // malformed = open
    public void Maintenance_window_evaluation(string window, string now, bool expected)
        => Assert.Equal(expected, AutomationService.IsWindowOpen(window, DateTimeOffset.Parse(now)));
}
