using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Infrastructure.Security;

/// <summary>
/// PKCS#11 token-backed keys (design doc §16.3). The private half is created on the token with
/// CKA_EXTRACTABLE=false and CKA_SENSITIVE=true, so it cannot be read out even by this code —
/// which is the whole point: a CSR is produced by asking the token to sign, never by handling key
/// material. Configuration: Hsm:Pkcs11:LibraryPath, TokenLabel, Pin.
/// </summary>
public class Pkcs11KeyProvider(IConfiguration configuration) : IKeyProvider
{
    public KeyProviderKind Kind => KeyProviderKind.Pkcs11;

    public bool Enabled =>
        !string.IsNullOrWhiteSpace(configuration["Hsm:Pkcs11:LibraryPath"])
        && !string.IsNullOrWhiteSpace(configuration["Hsm:Pkcs11:Pin"]);

    private string LibraryPath => configuration["Hsm:Pkcs11:LibraryPath"]!;
    private string Pin => configuration["Hsm:Pkcs11:Pin"]!;
    private string? TokenLabel => configuration["Hsm:Pkcs11:TokenLabel"];

    public Task<GeneratedKey> GenerateAsync(KeySpec spec, CancellationToken ct)
    {
        EnsureEnabled();
        if (!spec.Algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("The PKCS#11 provider currently issues RSA keys only.");

        using var session = OpenSession();
        var id = Guid.NewGuid().ToByteArray();
        var factories = session.Factories.ObjectAttributeFactory;

        var publicTemplate = new List<IObjectAttribute>
        {
            factories.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            factories.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            factories.Create(CKA.CKA_TOKEN, true),
            factories.Create(CKA.CKA_PRIVATE, false),
            factories.Create(CKA.CKA_LABEL, spec.Label),
            factories.Create(CKA.CKA_ID, id),
            factories.Create(CKA.CKA_VERIFY, true),
            factories.Create(CKA.CKA_MODULUS_BITS, (ulong)(spec.SizeOrCurve < 2048 ? 2048 : spec.SizeOrCurve)),
            factories.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 })
        };

        var privateTemplate = new List<IObjectAttribute>
        {
            factories.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            factories.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            factories.Create(CKA.CKA_TOKEN, true),
            factories.Create(CKA.CKA_PRIVATE, true),
            factories.Create(CKA.CKA_LABEL, spec.Label),
            factories.Create(CKA.CKA_ID, id),
            factories.Create(CKA.CKA_SIGN, true),
            factories.Create(CKA.CKA_SENSITIVE, true),
            // A token key is non-exportable by construction; an "exportable" request cannot be
            // honoured here, so it is refused rather than silently downgraded.
            factories.Create(CKA.CKA_EXTRACTABLE, false)
        };

        if (spec.Exportable)
            throw new InvalidOperationException(
                "PKCS#11 keys are created non-exportable; request a software key if the private half must be exportable.");

        using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        session.GenerateKeyPair(mechanism, publicTemplate, privateTemplate,
            out var publicKey, out _);

        var publicPem = ExportPublicKeyPem(session, publicKey);
        return Task.FromResult(new GeneratedKey($"pkcs11://{TokenLabel ?? "token"}/{spec.Label}", publicPem, null));
    }

    public Task<string> CreateCsrPemAsync(string reference, string subject, IReadOnlyList<string> sans,
        string? privateKeyPem, CancellationToken ct)
    {
        EnsureEnabled();
        var label = LabelOf(reference);
        using var session = OpenSession();
        var (privateKey, publicKey) = FindPair(session, label);

        using var rsa = new Pkcs11Rsa(session, privateKey, ReadPublicParameters(session, publicKey));
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SoftwareKeyProvider.AddSans(request, sans);
        return Task.FromResult(request.CreateSigningRequestPem());
    }

    public Task DestroyAsync(string reference, CancellationToken ct)
    {
        EnsureEnabled();
        var label = LabelOf(reference);
        using var session = OpenSession();
        foreach (var handle in FindByLabel(session, label))
            session.DestroyObject(handle);
        return Task.CompletedTask;
    }

    private void EnsureEnabled()
    {
        if (!Enabled)
            throw new InvalidOperationException(
                "PKCS#11 is not configured (Hsm:Pkcs11:LibraryPath, Hsm:Pkcs11:Pin).");
    }

    /// <summary>Opens a logged-in read/write session on the configured token.</summary>
    private ISession OpenSession()
    {
        var factories = new Pkcs11InteropFactories();
        var library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            factories, LibraryPath, AppType.MultiThreaded);

        var slots = library.GetSlotList(SlotsType.WithTokenPresent);
        var slot = TokenLabel is null
            ? slots.FirstOrDefault()
            : slots.FirstOrDefault(s => s.GetTokenInfo().Label.Trim() == TokenLabel.Trim());
        if (slot is null)
            throw new InvalidOperationException($"No PKCS#11 token found (label '{TokenLabel ?? "<any>"}').");

        var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, Pin);
        return session;
    }

    private static string LabelOf(string reference)
    {
        var path = reference.Replace("pkcs11://", string.Empty, StringComparison.OrdinalIgnoreCase).Trim('/');
        var slash = path.IndexOf('/');
        return slash < 0 ? path : path[(slash + 1)..];
    }

    private static List<IObjectHandle> FindByLabel(ISession session, string label)
    {
        var criteria = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label)
        };
        return session.FindAllObjects(criteria).ToList();
    }

    private static (IObjectHandle Private, IObjectHandle Public) FindPair(ISession session, string label)
    {
        var attrFactory = session.Factories.ObjectAttributeFactory;
        var priv = session.FindAllObjects(
        [
            attrFactory.Create(CKA.CKA_LABEL, label),
            attrFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
        ]).FirstOrDefault() ?? throw new InvalidOperationException($"No private key labelled '{label}' on the token.");

        var pub = session.FindAllObjects(
        [
            attrFactory.Create(CKA.CKA_LABEL, label),
            attrFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)
        ]).FirstOrDefault() ?? throw new InvalidOperationException($"No public key labelled '{label}' on the token.");

        return (priv, pub);
    }

    private static RSAParameters ReadPublicParameters(ISession session, IObjectHandle publicKey)
    {
        var attributes = session.GetAttributeValue(publicKey,
            [CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT]);
        return new RSAParameters
        {
            Modulus = attributes[0].GetValueAsByteArray(),
            Exponent = attributes[1].GetValueAsByteArray()
        };
    }

    private static string ExportPublicKeyPem(ISession session, IObjectHandle publicKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(ReadPublicParameters(session, publicKey));
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>
    /// An <see cref="RSA"/> whose private operations happen on the token. Only signing and the
    /// public parameters are available — every other member throws, because a token key genuinely
    /// cannot do them.
    /// </summary>
    private sealed class Pkcs11Rsa(ISession session, IObjectHandle privateKey, RSAParameters publicParameters) : RSA
    {
        public override RSAParameters ExportParameters(bool includePrivateParameters) =>
            includePrivateParameters
                ? throw new CryptographicException("A PKCS#11 private key cannot be exported.")
                : publicParameters;

        public override void ImportParameters(RSAParameters parameters) =>
            throw new NotSupportedException("A PKCS#11 key is created on the token, not imported.");

        public override int KeySize => (publicParameters.Modulus?.Length ?? 0) * 8;

        public override KeySizes[] LegalKeySizes => [new KeySizes(KeySize, KeySize, 0)];

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (padding != RSASignaturePadding.Pkcs1)
                throw new NotSupportedException("The PKCS#11 signer supports PKCS#1 v1.5 padding only.");

            // CKM_RSA_PKCS expects a DigestInfo, so the hash is wrapped before it goes to the token.
            using var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            return session.Sign(mechanism, privateKey, DigestInfo(hash, hashAlgorithm));
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            using var verifier = Create();
            verifier.ImportParameters(publicParameters);
            return verifier.VerifyHash(hash, signature, hashAlgorithm, padding);
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
            Hash(hashAlgorithm).ComputeHash(data, offset, count);

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
            Hash(hashAlgorithm).ComputeHash(data);

        private static HashAlgorithm Hash(HashAlgorithmName name) => name.Name switch
        {
            nameof(HashAlgorithmName.SHA384) => SHA384.Create(),
            nameof(HashAlgorithmName.SHA512) => SHA512.Create(),
            _ => SHA256.Create()
        };

        /// <summary>DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }, per RFC 8017.</summary>
        private static byte[] DigestInfo(byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            var oid = hashAlgorithm.Name switch
            {
                nameof(HashAlgorithmName.SHA384) => "2.16.840.1.101.3.4.2.2",
                nameof(HashAlgorithmName.SHA512) => "2.16.840.1.101.3.4.2.3",
                _ => "2.16.840.1.101.3.4.2.1"
            };

            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteNull();
                }
                writer.WriteOctetString(hash);
            }
            return writer.Encode();
        }

        protected override void Dispose(bool disposing) => base.Dispose(disposing);
    }
}
