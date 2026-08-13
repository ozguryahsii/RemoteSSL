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
    string Pem);

public static class CertificateParser
{
    public static ParsedCertificate Parse(byte[] der)
    {
        using var cert = new X509Certificate2(der);
        return Parse(cert);
    }

    public static ParsedCertificate Parse(X509Certificate2 cert)
    {
        var (alg, keySize) = GetPublicKeyInfo(cert);
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
            Pem: cert.ExportCertificatePem());
    }

    private static (string Algorithm, int KeySize) GetPublicKeyInfo(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is not null) return ("RSA", rsa.KeySize);
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa is not null) return ("EC", ecdsa.KeySize);
        return (cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unknown", 0);
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
