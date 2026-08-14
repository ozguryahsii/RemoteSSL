using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Infrastructure.Security;

/// <summary>
/// Keys generated inside the control plane (design doc §16.1 "central key generation"). The
/// private half is handed back to the caller once, at creation, so it can be encrypted before it
/// is stored; afterwards the caller passes it back in to sign a CSR. Non-exportable software keys
/// are honoured by the export API refusing to return them — the material itself is unavoidably in
/// the database, which is exactly why §16.3 offers a token provider as well.
/// </summary>
public class SoftwareKeyProvider : IKeyProvider
{
    public KeyProviderKind Kind => KeyProviderKind.Software;
    public bool Enabled => true;

    public Task<GeneratedKey> GenerateAsync(KeySpec spec, CancellationToken ct)
    {
        var key = Create(spec.Algorithm, spec.SizeOrCurve);
        return Task.FromResult(new GeneratedKey(
            $"software://{Guid.NewGuid():N}",
            key.PublicKeyPem,
            key.PrivateKeyPem));
    }

    public Task<string> CreateCsrPemAsync(string reference, string subject, IReadOnlyList<string> sans,
        string? privateKeyPem, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem))
            throw new InvalidOperationException("A software key needs its private key to sign a CSR.");

        // PKCS#8 does not say in its header which algorithm it carries, so the import decides.
        CertificateRequest request;
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(privateKeyPem);
            request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(privateKeyPem);
            request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        }

        AddSans(request, sans);
        return Task.FromResult(request.CreateSigningRequestPem());
    }

    public Task DestroyAsync(string reference, CancellationToken ct) => Task.CompletedTask;

    /// <summary>Adds a subjectAltName extension when there is anything to put in it.</summary>
    internal static void AddSans(CertificateRequest request, IReadOnlyList<string> sans)
    {
        if (sans.Count == 0) return;
        var builder = new SubjectAlternativeNameBuilder();
        foreach (var san in sans.Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            if (System.Net.IPAddress.TryParse(san, out var ip)) builder.AddIpAddress(ip);
            else builder.AddDnsName(san);
        }
        request.CertificateExtensions.Add(builder.Build());
    }

    private static (string PublicKeyPem, string PrivateKeyPem) Create(string algorithm, int sizeOrCurve)
    {
        if (algorithm.Equals("EC", StringComparison.OrdinalIgnoreCase) ||
            algorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = sizeOrCurve switch
            {
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP256
            };
            using var ecdsa = ECDsa.Create(curve);
            return (ecdsa.ExportSubjectPublicKeyInfoPem(), ecdsa.ExportPkcs8PrivateKeyPem());
        }

        using var rsa = RSA.Create(sizeOrCurve < 2048 ? 2048 : sizeOrCurve);
        return (rsa.ExportSubjectPublicKeyInfoPem(), rsa.ExportPkcs8PrivateKeyPem());
    }
}
