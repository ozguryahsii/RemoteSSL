using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Infrastructure.Security;

/// <summary>The identity handed to a runner at bootstrap: its certificate plus the issuing CA.</summary>
public sealed record IssuedRunnerIdentity(string CertificatePem, string CaCertificatePem, string Thumbprint);

/// <summary>
/// Issues client certificates to runners (design doc §8.2: "registration a bootstrap token ile
/// yapılır; ardından cihaz kimliği için client certificate üretilir"). The control plane keeps a
/// small internal CA for this — it is not a general PKI, only the trust anchor for runner
/// identity, so it never signs anything else.
/// </summary>
public class RunnerIdentityService(IRemoteSslDbContext db, ISecretProtector protector)
{
    private static readonly TimeSpan CertificateLifetime = TimeSpan.FromDays(397);

    /// <summary>
    /// Signs the runner's CSR with the internal CA. The runner generates its own key, so the
    /// private half of its identity never travels — the same principle as on-target keys (§16.1).
    /// </summary>
    public async Task<IssuedRunnerIdentity> IssueAsync(string runnerName, string csrPem, CancellationToken ct)
    {
        using var issuerCert = await LoadOrCreateAuthorityAsync(ct);
        {
            var request = CertificateRequest.LoadSigningRequestPem(csrPem, HashAlgorithmName.SHA256,
                signerSignaturePadding: RSASignaturePadding.Pkcs1);

            // A runner identity is a TLS client credential and nothing more.
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.2")], critical: true)); // clientAuth

            using var certificate = request.Create(issuerCert,
                DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.Add(CertificateLifetime),
                RandomNumberGenerator.GetBytes(16));

            return new IssuedRunnerIdentity(
                certificate.ExportCertificatePem(),
                issuerCert.ExportCertificatePem(),
                Convert.ToHexString(SHA256.HashData(certificate.RawData)));
        }
    }

    /// <summary>The CA certificate, so callers can pin it; created on first use.</summary>
    public async Task<string> GetAuthorityPemAsync(CancellationToken ct)
    {
        using var cert = await LoadOrCreateAuthorityAsync(ct);
        return cert.ExportCertificatePem();
    }

    /// <summary>
    /// The CA certificate with its private key attached, ready to sign. Created on first use
    /// and stored with the key encrypted; it is never exposed through any API.
    /// </summary>
    private async Task<X509Certificate2> LoadOrCreateAuthorityAsync(CancellationToken ct)
    {
        var existing = await db.RunnerAuthorities.FirstOrDefaultAsync(ct);
        if (existing is not null)
        {
            return X509Certificate2.CreateFromPem(
                existing.CertificatePem, protector.Unprotect(existing.EncryptedKeyPem));
        }

        using var caKey = RSA.Create(3072);
        var caRequest = new CertificateRequest("CN=RemoteSSL Runner CA", caKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        using var caCert = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(10));

        db.RunnerAuthorities.Add(new RunnerCertificateAuthority
        {
            Id = Guid.NewGuid(),
            CertificatePem = caCert.ExportCertificatePem(),
            EncryptedKeyPem = protector.Protect(caKey.ExportPkcs8PrivateKeyPem()),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(ct);

        return X509Certificate2.CreateFromPem(caCert.ExportCertificatePem(), caKey.ExportPkcs8PrivateKeyPem());
    }
}
