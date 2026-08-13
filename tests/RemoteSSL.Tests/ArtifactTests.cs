using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using RemoteSSL.Application.Artifacts;
using RemoteSSL.Application.Certificates;

namespace RemoteSSL.Tests;

public class EnvelopeCipherTests
{
    private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\nsecret\n");

    [Fact]
    public void Sealed_content_round_trips()
    {
        var sealedArtifact = EnvelopeCipher.Seal(Plaintext);
        var opened = EnvelopeCipher.Open(sealedArtifact.Ciphertext, sealedArtifact.Nonce,
            sealedArtifact.Tag, sealedArtifact.DataKey);
        Assert.Equal(Plaintext, opened);
    }

    [Fact]
    public void Ciphertext_does_not_contain_the_plaintext()
    {
        var sealedArtifact = EnvelopeCipher.Seal(Plaintext);
        Assert.DoesNotContain("secret", Encoding.UTF8.GetString(sealedArtifact.Ciphertext));
    }

    [Fact]
    public void Every_artifact_gets_its_own_data_key_and_nonce()
    {
        var a = EnvelopeCipher.Seal(Plaintext);
        var b = EnvelopeCipher.Seal(Plaintext);
        Assert.NotEqual(a.DataKey, b.DataKey);
        Assert.NotEqual(a.Nonce, b.Nonce);
        Assert.NotEqual(a.Ciphertext, b.Ciphertext);
    }

    [Fact]
    public void Hash_is_of_the_plaintext_so_integrity_can_be_checked_after_opening()
    {
        var sealedArtifact = EnvelopeCipher.Seal(Plaintext);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Plaintext)), sealedArtifact.Sha256);
    }

    [Fact]
    public void Tampered_ciphertext_is_refused_rather_than_returned()
    {
        var sealedArtifact = EnvelopeCipher.Seal(Plaintext);
        sealedArtifact.Ciphertext[0] ^= 0xFF;
        // AesGcm reports the tag mismatch as a CryptographicException subclass.
        Assert.ThrowsAny<CryptographicException>(() =>
            EnvelopeCipher.Open(sealedArtifact.Ciphertext, sealedArtifact.Nonce, sealedArtifact.Tag, sealedArtifact.DataKey));
    }

    [Fact]
    public void A_different_data_key_cannot_open_the_artifact()
    {
        var sealedArtifact = EnvelopeCipher.Seal(Plaintext);
        var otherKey = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<CryptographicException>(() =>
            EnvelopeCipher.Open(sealedArtifact.Ciphertext, sealedArtifact.Nonce, sealedArtifact.Tag, otherKey));
    }
}

/// <summary>Format engine coverage (§15.2, FR-006) over a self-signed certificate + key.</summary>
public class FormatConverterTests
{
    private static (string CertPem, string KeyPem) SelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=convert.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return (new string(PemEncoding.Write("CERTIFICATE", cert.RawData)),
            new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey())));
    }

    [Fact]
    public void Pem_output_returns_the_certificate()
    {
        var (certPem, _) = SelfSigned();
        var result = FormatConverter.Convert("pem", certPem, null, null, null, null, null, null);
        Assert.Contains("BEGIN CERTIFICATE", Encoding.UTF8.GetString(result.Content));
        Assert.False(result.ContainsPrivateKey);
    }

    [Fact]
    public void Der_output_is_the_raw_certificate()
    {
        var (certPem, _) = SelfSigned();
        var result = FormatConverter.Convert("der", certPem, null, null, null, null, null, null);
        using var parsed = new X509Certificate2(result.Content);
        Assert.Equal("CN=convert.test", parsed.Subject);
    }

    [Fact]
    public void Pfx_round_trips_back_to_pem_and_key()
    {
        var (certPem, keyPem) = SelfSigned();
        var pfx = FormatConverter.Convert("pfx", certPem, keyPem, null, null, null, "pw", null);
        Assert.True(pfx.ContainsPrivateKey);

        var backToKey = FormatConverter.Convert("key", null, null, null, pfx.Content, null, "pw", null);
        Assert.Contains("PRIVATE KEY", Encoding.UTF8.GetString(backToKey.Content));
    }

    [Fact]
    public void Pfx_output_without_a_key_is_refused_instead_of_producing_a_useless_file()
    {
        var (certPem, _) = SelfSigned();
        var ex = Assert.Throws<ArgumentException>(() =>
            FormatConverter.Convert("pfx", certPem, null, null, null, null, "pw", null));
        Assert.Contains("private key", ex.Message);
    }

    [Fact]
    public void Jks_with_a_key_is_a_readable_java_keystore_with_the_requested_alias()
    {
        var (certPem, keyPem) = SelfSigned();
        var jks = FormatConverter.Convert("jks", certPem, keyPem, null, null, null, "storepass", "app");
        Assert.True(jks.ContainsPrivateKey);

        var store = new Org.BouncyCastle.Security.JksStore();
        using var stream = new MemoryStream(jks.Content);
        store.Load(stream, "storepass".ToCharArray());
        Assert.True(store.IsKeyEntry("app"));
    }

    [Fact]
    public void Jks_without_a_key_produces_a_truststore_entry()
    {
        var (certPem, _) = SelfSigned();
        var jks = FormatConverter.Convert("jks", certPem, null, null, null, null, "storepass", "root");
        Assert.False(jks.ContainsPrivateKey);

        var store = new Org.BouncyCastle.Security.JksStore();
        using var stream = new MemoryStream(jks.Content);
        store.Load(stream, "storepass".ToCharArray());
        Assert.True(store.IsCertificateEntry("root"));
    }

    [Fact]
    public void Unknown_target_format_names_what_is_supported()
    {
        var (certPem, _) = SelfSigned();
        var ex = Assert.Throws<ArgumentException>(() =>
            FormatConverter.Convert("xyz", certPem, null, null, null, null, null, null));
        Assert.Contains("pem", ex.Message);
    }
}

/// <summary>Chain assembly and gap detection (§15.3, FR-008).</summary>
public class ChainBuilderTests
{
    private static (X509Certificate2 Root, X509Certificate2 Intermediate, X509Certificate2 Leaf) Hierarchy()
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        using var interKey = RSA.Create(2048);
        var interRequest = new CertificateRequest("CN=Test Intermediate", interKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        interRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var intermediate = interRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(3), Guid.NewGuid().ToByteArray());

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=app.test", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signer = intermediate.CopyWithPrivateKey(interKey);
        var leaf = leafRequest.Create(signer, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90), Guid.NewGuid().ToByteArray());

        return (root, intermediate, leaf);
    }

    private static string Pem(X509Certificate2 cert) => new(PemEncoding.Write("CERTIFICATE", cert.RawData));

    [Fact]
    public void Complete_chain_is_recognised_and_ordered_leaf_first()
    {
        var (root, intermediate, leaf) = Hierarchy();
        var analysis = ChainBuilder.Analyze(Pem(leaf), Pem(intermediate) + Pem(root));

        Assert.True(analysis.Complete);
        Assert.Empty(analysis.MissingIssuers);
        var path = Assert.Single(analysis.Paths);
        Assert.Equal(["CN=app.test", "CN=Test Intermediate", "CN=Test Root"], path.Select(l => l.Subject));
        Assert.True(path[^1].SelfSigned);
    }

    [Fact]
    public void Missing_intermediate_is_named_rather_than_silently_ignored()
    {
        var (root, _, leaf) = Hierarchy();
        var analysis = ChainBuilder.Analyze(Pem(leaf), Pem(root));

        Assert.False(analysis.Complete);
        Assert.Contains("CN=Test Intermediate", Assert.Single(analysis.MissingIssuers));
    }

    [Fact]
    public void Building_an_incomplete_chain_for_deployment_is_refused()
    {
        var (root, _, leaf) = Hierarchy();
        var ex = Assert.Throws<InvalidOperationException>(() => ChainBuilder.BuildOrdered(Pem(leaf), Pem(root)));
        Assert.Contains("incomplete", ex.Message);
    }

    [Fact]
    public void Ordered_chain_excludes_the_root_unless_asked()
    {
        var (root, intermediate, leaf) = Hierarchy();
        var pool = Pem(intermediate) + Pem(root);

        var withoutRoot = ChainBuilder.BuildOrdered(Pem(leaf), pool);
        Assert.Single(CertificateFactory.ParsePemCertificates(withoutRoot));

        var withRoot = ChainBuilder.BuildOrdered(Pem(leaf), pool, includeRoot: true);
        Assert.Equal(2, CertificateFactory.ParsePemCertificates(withRoot).Count());
    }

    [Fact]
    public void Cross_signed_issuers_produce_one_path_each()
    {
        var (root, intermediate, leaf) = Hierarchy();

        // A second root signs a certificate with the same subject and key as the intermediate,
        // which is exactly the cross-signing case §15.3 asks to surface.
        using var otherRootKey = RSA.Create(2048);
        var otherRootRequest = new CertificateRequest("CN=Other Root", otherRootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        otherRootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var otherRoot = otherRootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(5));

        var crossRequest = new CertificateRequest(
            intermediate.SubjectName, intermediate.PublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        crossRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var crossSigned = crossRequest.Create(otherRoot, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(3), Guid.NewGuid().ToByteArray());

        var analysis = ChainBuilder.Analyze(Pem(leaf), Pem(intermediate) + Pem(crossSigned) + Pem(root) + Pem(otherRoot));

        Assert.Equal(2, analysis.Paths.Count);
        Assert.Contains(analysis.Paths, p => p[^1].Subject == "CN=Test Root");
        Assert.Contains(analysis.Paths, p => p[^1].Subject == "CN=Other Root");
        Assert.Contains(analysis.Warnings, w => w.Contains("cross-signed"));
    }
}
