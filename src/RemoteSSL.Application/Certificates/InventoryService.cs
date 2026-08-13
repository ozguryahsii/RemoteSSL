using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Certificates;

/// <summary>Shared inventory write-path: issued/uploaded certificates become versions of a logical certificate.</summary>
public class InventoryService(IRemoteSslDbContext db)
{
    public async Task<CertificateVersion> AddVersionAsync(
        string certPem, string? chainPem, string? encryptedKeyPem,
        CertificateVersionStatus status, CancellationToken ct)
    {
        var parsed = CertificateParser.Parse(
            System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(certPem).RawData);

        var existing = await db.CertificateVersions.Include(v => v.Certificate)
            .FirstOrDefaultAsync(v => v.Sha256Thumbprint == parsed.Sha256Thumbprint, ct);
        if (existing is not null)
        {
            if (encryptedKeyPem is not null && existing.EncryptedPrivateKeyPem is null)
                existing.EncryptedPrivateKeyPem = encryptedKeyPem;
            return existing;
        }

        var now = DateTimeOffset.UtcNow;
        var certificate = await db.Certificates.FirstOrDefaultAsync(c => c.CommonName == parsed.CommonName, ct);
        if (certificate is null)
        {
            certificate = new Certificate
            {
                Id = Guid.NewGuid(),
                CommonName = parsed.CommonName,
                DisplayName = parsed.CommonName,
                HealthStatus = Monitoring.ExpiryCalculator.HealthFor(parsed.NotAfter, now),
                CreatedAt = now,
                UpdatedAt = now
            };
            db.Certificates.Add(certificate);
        }

        var version = new CertificateVersion
        {
            Id = Guid.NewGuid(),
            CertificateId = certificate.Id,
            Certificate = certificate,
            SerialNumber = parsed.SerialNumber,
            Sha256Thumbprint = parsed.Sha256Thumbprint,
            Sha1Thumbprint = parsed.Sha1Thumbprint,
            SubjectDn = parsed.SubjectDn,
            IssuerDn = parsed.IssuerDn,
            NotBefore = parsed.NotBefore,
            NotAfter = parsed.NotAfter,
            PublicKeyAlgorithm = parsed.PublicKeyAlgorithm,
            KeySize = parsed.KeySize,
            SignatureAlgorithm = parsed.SignatureAlgorithm,
            Status = status,
            PemCertificate = parsed.Pem,
            PemChain = chainPem,
            EncryptedPrivateKeyPem = encryptedKeyPem,
            CreatedAt = now
        };
        foreach (var (type, value) in parsed.Sans)
            version.Sans.Add(new CertificateSan { Id = Guid.NewGuid(), SanType = type, Value = value });
        db.CertificateVersions.Add(version);
        return version;
    }
}
