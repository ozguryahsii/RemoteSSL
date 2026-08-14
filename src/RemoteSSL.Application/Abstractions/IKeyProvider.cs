using RemoteSSL.Domain;

namespace RemoteSSL.Application.Abstractions;

/// <summary>What a key should be, before it exists (§16.3).</summary>
/// <param name="Algorithm">"RSA" or "EC".</param>
/// <param name="SizeOrCurve">RSA modulus size, or the EC curve size in bits (256/384/521).</param>
/// <param name="Label">Human-readable label; for PKCS#11 it becomes the token object label.</param>
/// <param name="Exportable">
/// The export policy. False means the private half can never be read back — the only way to keep
/// that promise for a software key is to refuse the export, and for a token key it is enforced by
/// the token itself (CKA_EXTRACTABLE=false).
/// </param>
public sealed record KeySpec(string Algorithm, int SizeOrCurve, string Label, bool Exportable);

/// <summary>
/// A key that now exists somewhere. <paramref name="Reference"/> is how the provider finds it
/// again; <paramref name="PrivateKeyPem"/> is only ever populated by the software provider, and
/// the caller is expected to encrypt it before it touches storage.
/// </summary>
public sealed record GeneratedKey(string Reference, string PublicKeyPem, string? PrivateKeyPem);

/// <summary>
/// A place where private keys are created and used (design doc §16.3). The abstraction exists so
/// that a certificate request does not care whether its key lives in the control plane's database
/// or inside an HSM: it asks for a key, then asks for a CSR, and the private half never moves.
/// </summary>
public interface IKeyProvider
{
    KeyProviderKind Kind { get; }
    /// <summary>False when the provider is compiled in but not configured; it is then never offered.</summary>
    bool Enabled { get; }

    Task<GeneratedKey> GenerateAsync(KeySpec spec, CancellationToken ct);

    /// <summary>
    /// Produces a PKCS#10 CSR signed by the referenced key. For token-backed keys the signature is
    /// computed on the token, so this is the only way to get a CSR out of a non-exportable key.
    /// </summary>
    Task<string> CreateCsrPemAsync(string reference, string subject, IReadOnlyList<string> sans,
        string? privateKeyPem, CancellationToken ct);

    /// <summary>Destroys the key material. Software keys are simply forgotten by the caller.</summary>
    Task DestroyAsync(string reference, CancellationToken ct);
}
