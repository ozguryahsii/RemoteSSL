using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Domain;

namespace RemoteSSL.Application.Certificates;

/// <summary>All fields extracted from one X.509 certificate (design doc §6.2).</summary>
public sealed record ParsedCertificate(
    string SubjectDn,
    string CommonName,
    string IssuerDn,
    string SerialNumber,
    string Sha256Thumbprint,
    string Sha1Thumbprint,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string PublicKeyAlgorithm,
    int KeySize,
    string SignatureAlgorithm,
    IReadOnlyList<(SanType Type, string Value)> Sans,
    string Pem,
    bool IsCertificateAuthority,
    int? PathLengthConstraint,
    IReadOnlyList<string> KeyUsages,
    IReadOnlyList<string> ExtendedKeyUsages,
    IReadOnlyList<string> CaIssuerUrls,
    IReadOnlyList<string> OcspUrls,
    IReadOnlyList<string> CrlDistributionPoints);

public static class CertificateParser
{
    private const string AuthorityInfoAccessOid = "1.3.6.1.5.5.7.1.1";
    private const string CrlDistributionPointsOid = "2.5.29.31";
    private const string CaIssuersAccessMethod = "1.3.6.1.5.5.7.48.2";
    private const string OcspAccessMethod = "1.3.6.1.5.5.7.48.1";

    public static ParsedCertificate Parse(byte[] der)
    {
        using var cert = new X509Certificate2(der);
        return Parse(cert);
    }

    public static ParsedCertificate Parse(X509Certificate2 cert)
    {
        var (alg, keySize) = GetPublicKeyInfo(cert);
        var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        return new ParsedCertificate(
            SubjectDn: cert.SubjectName.Name,
            CommonName: cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
            IssuerDn: cert.IssuerName.Name,
            SerialNumber: cert.SerialNumber,
            Sha256Thumbprint: Convert.ToHexString(SHA256.HashData(cert.RawData)),
            Sha1Thumbprint: cert.Thumbprint,
            NotBefore: cert.NotBefore.ToUniversalTime(),
            NotAfter: cert.NotAfter.ToUniversalTime(),
            PublicKeyAlgorithm: alg,
            KeySize: keySize,
            SignatureAlgorithm: cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown",
            Sans: ExtractSans(cert),
            Pem: cert.ExportCertificatePem(),
            IsCertificateAuthority: basicConstraints?.CertificateAuthority ?? false,
            PathLengthConstraint: basicConstraints is { HasPathLengthConstraint: true }
                ? basicConstraints.PathLengthConstraint : null,
            KeyUsages: ExtractKeyUsages(cert),
            ExtendedKeyUsages: ExtractExtendedKeyUsages(cert),
            CaIssuerUrls: AuthorityInfoAccess(cert, CaIssuersAccessMethod),
            OcspUrls: AuthorityInfoAccess(cert, OcspAccessMethod),
            CrlDistributionPoints: ExtractCrlDistributionPoints(cert));
    }

    private static (string Algorithm, int KeySize) GetPublicKeyInfo(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is not null) return ("RSA", rsa.KeySize);
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa is not null) return ("EC", ecdsa.KeySize);
        return (cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unknown", 0);
    }

    /// <summary>Key usages as their standard names, in extension order (§6.2).</summary>
    private static IReadOnlyList<string> ExtractKeyUsages(X509Certificate2 cert)
    {
        var extension = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (extension is null) return [];

        var flags = extension.KeyUsages;
        var names = new List<string>();
        foreach (var value in Enum.GetValues<X509KeyUsageFlags>())
        {
            if (value != X509KeyUsageFlags.None && flags.HasFlag(value)) names.Add(value.ToString());
        }
        return names;
    }

    /// <summary>Extended key usages, with the well-known OIDs given readable names (§6.2).</summary>
    private static IReadOnlyList<string> ExtractExtendedKeyUsages(X509Certificate2 cert)
    {
        var extension = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (extension is null) return [];
        return extension.EnhancedKeyUsages.OfType<Oid>()
            .Select(o => o.FriendlyName ?? o.Value ?? "unknown")
            .ToList();
    }

    /// <summary>CA Issuers / OCSP URLs from the Authority Information Access extension (§6.2).</summary>
    private static IReadOnlyList<string> AuthorityInfoAccess(X509Certificate2 cert, string accessMethod)
    {
        var extension = cert.Extensions[AuthorityInfoAccessOid];
        if (extension is null) return [];

        try
        {
            var urls = new List<string>();
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (reader.HasData)
            {
                var description = reader.ReadSequence();
                var method = description.ReadObjectIdentifier();
                var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
                if (!description.HasData || !description.PeekTag().HasSameClassAndValue(uriTag)) continue;
                var url = description.ReadCharacterString(UniversalTagNumber.IA5String, uriTag);
                if (method == accessMethod) urls.Add(url);
            }
            return urls;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }

    /// <summary>CRL distribution point URLs (§6.2 CDP metadata).</summary>
    private static IReadOnlyList<string> ExtractCrlDistributionPoints(X509Certificate2 cert)
    {
        var extension = cert.Extensions[CrlDistributionPointsOid];
        if (extension is null) return [];

        try
        {
            var urls = new List<string>();
            var points = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (points.HasData)
            {
                // DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT ... }
                var point = points.ReadSequence();
                if (!point.HasData) continue;
                var nameTag = new Asn1Tag(TagClass.ContextSpecific, 0);
                if (!point.PeekTag().HasSameClassAndValue(nameTag)) continue;

                var fullNameTag = new Asn1Tag(TagClass.ContextSpecific, 0);
                var names = point.ReadSequence(nameTag).ReadSequence(fullNameTag);
                var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
                while (names.HasData)
                {
                    if (!names.PeekTag().HasSameClassAndValue(uriTag)) { names.ReadEncodedValue(); continue; }
                    urls.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag));
                }
            }
            return urls;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }

    private static List<(SanType, string)> ExtractSans(X509Certificate2 cert)
    {
        var sans = new List<(SanType, string)>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is not X509SubjectAlternativeNameExtension sanExt) continue;
            sans.AddRange(sanExt.EnumerateDnsNames().Select(d => (SanType.Dns, d)));
            sans.AddRange(sanExt.EnumerateIPAddresses().Select(ip => (SanType.Ip, ip.ToString())));
        }
        return sans;
    }
}
