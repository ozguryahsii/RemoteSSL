using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RemoteSSL.Application.Certificates;

/// <summary>
/// Central crypto engine (design doc §15): key + CSR generation, format conversion
/// (PEM/PFX/P7B), chain assembly. Pure functions; artifact persistence policy is the
/// caller's concern. Private keys are returned, never stored here.
/// </summary>
public static class CertificateFactory
{
    public sealed record CsrArtifacts(string CsrPem, string PrivateKeyPem);

    /// <summary>Optional subject DN attributes beyond CN (design doc §17.1 wizard fields).</summary>
    public sealed record SubjectOptions(
        string? Organization = null, string? OrganizationalUnit = null,
        string? Locality = null, string? State = null, string? Country = null);

    public static string BuildSubjectDn(string commonName, SubjectOptions? subject)
    {
        static string Esc(string v) => v.Replace("\\", "\\\\").Replace(",", "\\,").Replace("+", "\\+");
        var parts = new List<string> { $"CN={Esc(commonName)}" };
        if (subject is not null)
        {
            if (!string.IsNullOrWhiteSpace(subject.Organization)) parts.Add($"O={Esc(subject.Organization)}");
            if (!string.IsNullOrWhiteSpace(subject.OrganizationalUnit)) parts.Add($"OU={Esc(subject.OrganizationalUnit)}");
            if (!string.IsNullOrWhiteSpace(subject.Locality)) parts.Add($"L={Esc(subject.Locality)}");
            if (!string.IsNullOrWhiteSpace(subject.State)) parts.Add($"ST={Esc(subject.State)}");
            if (!string.IsNullOrWhiteSpace(subject.Country)) parts.Add($"C={Esc(subject.Country.ToUpperInvariant())}");
        }
        return string.Join(", ", parts);
    }

    public static CsrArtifacts GenerateCsr(
        string commonName, IReadOnlyList<string> dnsSans, string keyAlgorithm, int keySizeOrCurve,
        SubjectOptions? subject = null)
    {
        var subjectDn = BuildSubjectDn(commonName, subject);
        AsymmetricAlgorithm key;
        CertificateRequest req;
        if (keyAlgorithm.Equals("EC", StringComparison.OrdinalIgnoreCase)
            || keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = keySizeOrCurve switch
            {
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP256
            };
            var ecdsa = ECDsa.Create(curve);
            key = ecdsa;
            req = new CertificateRequest(new System.Security.Cryptography.X509Certificates.X500DistinguishedName(subjectDn), ecdsa, HashAlgorithmName.SHA256);
        }
        else
        {
            if (keySizeOrCurve < 2048)
                throw new ArgumentException("RSA key size below policy minimum 2048.");
            var rsa = RSA.Create(keySizeOrCurve);
            key = rsa;
            req = new CertificateRequest(new System.Security.Cryptography.X509Certificates.X500DistinguishedName(subjectDn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using (key)
        {
            if (dnsSans.Count > 0)
            {
                var san = new SubjectAlternativeNameBuilder();
                foreach (var dns in dnsSans.Distinct(StringComparer.OrdinalIgnoreCase)) san.AddDnsName(dns);
                req.CertificateExtensions.Add(san.Build());
            }
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));

            var csrPem = req.CreateSigningRequestPem();
            var keyPem = key switch
            {
                RSA r => r.ExportPkcs8PrivateKeyPem(),
                ECDsa e => e.ExportPkcs8PrivateKeyPem(),
                _ => throw new InvalidOperationException()
            };
            return new CsrArtifacts(csrPem, keyPem);
        }
    }

    /// <summary>CRT/KEY/chain PEM → PFX (PKCS#12) bytes.</summary>
    public static byte[] BuildPfx(string certPem, string keyPem, string? chainPem, string password)
    {
        using var leaf = X509Certificate2.CreateFromPem(certPem, keyPem);
        var collection = new X509Certificate2Collection { leaf };
        foreach (var c in ParsePemCertificates(chainPem)) collection.Add(c);
        return collection.Export(X509ContentType.Pfx, password)!;
    }

    public sealed record PfxContents(string LeafPem, string PrivateKeyPem, string ChainPem);

    /// <summary>PFX → leaf.pem + key.pem + chain.pem.</summary>
    public static PfxContents ParsePfx(byte[] pfx, string password)
    {
        var collection = new X509Certificate2Collection();
        collection.Import(pfx, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        var leaf = collection.Cast<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey)
                   ?? throw new ArgumentException("PFX contains no private-key entry.");

        string keyPem;
        using (RSA? rsa = leaf.GetRSAPrivateKey())
        {
            if (rsa is not null) keyPem = rsa.ExportPkcs8PrivateKeyPem();
            else
            {
                using var ec = leaf.GetECDsaPrivateKey() ?? throw new ArgumentException("Unsupported key type in PFX.");
                keyPem = ec.ExportPkcs8PrivateKeyPem();
            }
        }

        var chain = new StringBuilder();
        foreach (var c in collection.Cast<X509Certificate2>().Where(c => !c.Equals(leaf)))
            chain.AppendLine(c.ExportCertificatePem());

        return new PfxContents(leaf.ExportCertificatePem(), keyPem, chain.ToString().Trim());
    }

    /// <summary>P7B/PKCS#7 → ordered PEM certificate list.</summary>
    public static string ConvertP7bToPem(byte[] p7b)
    {
        var certs = new X509Certificate2Collection();
        certs.Import(p7b);
        return string.Join('\n', certs.Cast<X509Certificate2>().Select(c => c.ExportCertificatePem()));
    }

    /// <summary>
    /// Orders leaf + pool into leaf→intermediate(s) chain by issuer/subject matching
    /// (design doc §15.3). Root is excluded unless includeRoot.
    /// </summary>
    public static string BuildOrderedChain(string leafPem, string intermediatesPem, bool includeRoot = false)
    {
        using var leaf = X509Certificate2.CreateFromPem(leafPem);
        var pool = ParsePemCertificates(intermediatesPem).ToList();
        var ordered = new List<X509Certificate2>();
        var current = leaf;

        while (true)
        {
            if (current.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData)) break; // self-signed
            var issuer = pool.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData));
            if (issuer is null) break;
            pool.Remove(issuer);
            var isRoot = issuer.SubjectName.RawData.AsSpan().SequenceEqual(issuer.IssuerName.RawData);
            if (!isRoot || includeRoot) ordered.Add(issuer);
            if (isRoot) break;
            current = issuer;
        }

        var sb = new StringBuilder();
        foreach (var c in ordered) sb.AppendLine(c.ExportCertificatePem());
        foreach (var c in pool) c.Dispose();
        return sb.ToString().Trim();
    }

    /// <summary>True when every non-self-signed cert in the chain finds its issuer next in line.</summary>
    public static bool ValidateChainOrder(string leafPem, string chainPem)
    {
        using var leaf = X509Certificate2.CreateFromPem(leafPem);
        var chain = ParsePemCertificates(chainPem).ToList();
        try
        {
            var current = leaf;
            foreach (var next in chain)
            {
                if (!current.IssuerName.RawData.AsSpan().SequenceEqual(next.SubjectName.RawData)) return false;
                current = next;
            }
            return true;
        }
        finally
        {
            foreach (var c in chain) c.Dispose();
        }
    }

    public static IEnumerable<X509Certificate2> ParsePemCertificates(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) yield break;
        const string header = "-----BEGIN CERTIFICATE-----";
        const string footer = "-----END CERTIFICATE-----";
        var idx = 0;
        while ((idx = pem.IndexOf(header, idx, StringComparison.Ordinal)) >= 0)
        {
            var end = pem.IndexOf(footer, idx, StringComparison.Ordinal);
            if (end < 0) break;
            var block = pem[idx..(end + footer.Length)];
            idx = end + footer.Length;
            yield return X509Certificate2.CreateFromPem(block);
        }
    }
}
