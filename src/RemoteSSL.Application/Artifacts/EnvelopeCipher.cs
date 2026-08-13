using System.Security.Cryptography;

namespace RemoteSSL.Application.Artifacts;

/// <summary>Result of sealing one artifact: ciphertext plus everything needed to open it again.</summary>
public sealed record SealedArtifact(byte[] Ciphertext, byte[] Nonce, byte[] Tag, byte[] DataKey, string Sha256);

/// <summary>
/// Envelope encryption for artifacts (design doc §31.2): every artifact gets its own random
/// AES-256-GCM data key, and that key is wrapped by a key-encryption key held outside this
/// class (DataProtection today, KMS/HSM where one exists). Compromising one stored object
/// therefore never yields more than that object.
/// </summary>
public static class EnvelopeCipher
{
    private const int KeySize = 32;   // AES-256
    private const int NonceSize = 12; // GCM standard nonce
    private const int TagSize = 16;

    public static SealedArtifact Seal(byte[] plaintext)
    {
        var dataKey = RandomNumberGenerator.GetBytes(KeySize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(dataKey, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

        return new SealedArtifact(ciphertext, nonce, tag, dataKey,
            Convert.ToHexString(SHA256.HashData(plaintext)));
    }

    public static byte[] Open(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] dataKey)
    {
        var plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(dataKey, TagSize);
        // Throws CryptographicException when the tag does not match — a tampered or
        // truncated artifact must never be handed back as if it were intact.
        gcm.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
