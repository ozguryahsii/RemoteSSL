using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace RemoteSSL.Application.Certificates;

/// <summary>What a conversion produced, ready to hand back or store as an artifact.</summary>
public sealed record ConversionResult(byte[] Content, string ContentType, string FileExtension, bool ContainsPrivateKey);

/// <summary>
/// The format engine of design doc §15: one conversion surface across PEM/CRT/CER, PKCS#7,
/// PKCS#12 (PFX) and Java keystores, plus chain and fullchain assembly. Conversions that
/// would need a private key say so instead of quietly producing a certificate-only file.
/// </summary>
public static class FormatConverter
{
    /// <summary>Formats accepted as a conversion target (FR-006).</summary>
    public static readonly string[] SupportedTargets =
        ["pem", "crt", "cer", "der", "p7b", "pfx", "p12", "jks", "chain", "fullchain", "key"];

    public static ConversionResult Convert(
        string to, string? certPem, string? keyPem, string? chainPem, byte[]? pfx, byte[]? p7b,
        string? password, string? alias)
    {
        // Normalize whatever came in into leaf + chain + key.
        var (leaf, chain, key) = Normalize(certPem, keyPem, chainPem, pfx, p7b, password);

        return to.ToLowerInvariant() switch
        {
            "pem" or "crt" or "cer" => new ConversionResult(
                Encoding.UTF8.GetBytes(RequireLeaf(leaf)), "application/x-pem-file", to.ToLowerInvariant(), false),

            "der" => new ConversionResult(
                X509Certificate2.CreateFromPem(RequireLeaf(leaf)).RawData,
                "application/pkix-cert", "der", false),

            "chain" => new ConversionResult(
                Encoding.UTF8.GetBytes(chain ?? throw new ArgumentException("No chain available to convert.")),
                "application/x-pem-file", "chain.pem", false),

            "fullchain" => new ConversionResult(
                Encoding.UTF8.GetBytes(RequireLeaf(leaf).TrimEnd() + "\n" + (chain ?? string.Empty).TrimEnd() + "\n"),
                "application/x-pem-file", "fullchain.pem", false),

            "key" => new ConversionResult(
                Encoding.UTF8.GetBytes(key ?? throw new ArgumentException(
                    "The input carries no private key, so a key file cannot be produced.")),
                "application/x-pem-file", "key.pem", true),

            "p7b" => new ConversionResult(BuildP7b(RequireLeaf(leaf), chain), "application/x-pkcs7-certificates", "p7b", false),

            "pfx" or "p12" => new ConversionResult(
                CertificateFactory.BuildPfx(RequireLeaf(leaf),
                    key ?? throw new ArgumentException("PFX output requires the private key."),
                    chain, password ?? throw new ArgumentException("PFX output requires a password.")),
                "application/x-pkcs12", to.ToLowerInvariant(), true),

            "jks" => new ConversionResult(
                BuildJks(RequireLeaf(leaf), key, chain,
                    password ?? throw new ArgumentException("JKS output requires a store password."),
                    alias ?? "remotessl"),
                "application/x-java-keystore", "jks", key is not null),

            _ => throw new ArgumentException(
                $"Unsupported target format '{to}'. Supported: {string.Join(", ", SupportedTargets)}.")
        };
    }

    private static string RequireLeaf(string? leaf) =>
        leaf ?? throw new ArgumentException("No certificate found in the input.");

    private static (string? Leaf, string? Chain, string? Key) Normalize(
        string? certPem, string? keyPem, string? chainPem, byte[]? pfx, byte[]? p7b, string? password)
    {
        if (pfx is not null)
        {
            var parsed = CertificateFactory.ParsePfx(pfx,
                password ?? throw new ArgumentException("Reading a PFX requires its password."));
            return (parsed.LeafPem, parsed.ChainPem, parsed.PrivateKeyPem);
        }

        if (p7b is not null)
        {
            // A PKCS#7 bundle is certificates only: first is the leaf, the rest is the chain.
            var pem = CertificateFactory.ConvertP7bToPem(p7b);
            var certs = CertificateFactory.ParsePemCertificates(pem).ToList();
            var leafFromP7b = certs.FirstOrDefault();
            var rest = certs.Skip(1).ToList();
            return (leafFromP7b is null ? null : ToPem(leafFromP7b),
                rest.Count == 0 ? null : string.Join("\n", rest.Select(ToPem)),
                keyPem);
        }

        return (certPem, chainPem, keyPem);
    }

    private static string ToPem(X509Certificate2 cert) =>
        new(PemEncoding.Write("CERTIFICATE", cert.RawData));

    private static byte[] BuildP7b(string leafPem, string? chainPem)
    {
        var collection = new X509Certificate2Collection();
        collection.Add(X509Certificate2.CreateFromPem(leafPem));
        foreach (var c in CertificateFactory.ParsePemCertificates(chainPem)) collection.Add(c);
        return collection.Export(X509ContentType.Pkcs7)
               ?? throw new InvalidOperationException("PKCS#7 export produced no content.");
    }

    /// <summary>
    /// Writes a real Java keystore. With a private key the entry is a PrivateKeyEntry carrying
    /// the ordered chain (what an application server needs); without one it is a trusted
    /// certificate entry (what a truststore needs) — §12.1/§12.3.
    /// </summary>
    private static byte[] BuildJks(string leafPem, string? keyPem, string? chainPem, string password, string alias)
    {
        var store = new JksStore();
        var leaf = DotNetUtilities.FromX509Certificate(X509Certificate2.CreateFromPem(leafPem));

        if (keyPem is null)
        {
            store.SetCertificateEntry(alias, leaf);
            var index = 0;
            foreach (var c in CertificateFactory.ParsePemCertificates(chainPem))
                store.SetCertificateEntry($"{alias}-ca-{++index}", DotNetUtilities.FromX509Certificate(c));
        }
        else
        {
            var chain = new List<BcX509Certificate> { leaf };
            chain.AddRange(CertificateFactory.ParsePemCertificates(chainPem).Select(DotNetUtilities.FromX509Certificate));

            using var reader = new StringReader(keyPem);
            var keyObject = new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
            var privateKey = keyObject switch
            {
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair => pair.Private,
                Org.BouncyCastle.Crypto.AsymmetricKeyParameter k when k.IsPrivate => k,
                _ => throw new ArgumentException("The supplied key is not a readable private key.")
            };
            store.SetKeyEntry(alias, privateKey, password.ToCharArray(), [.. chain]);
        }

        using var output = new MemoryStream();
        store.Save(output, password.ToCharArray());
        return output.ToArray();
    }
}
