namespace RemoteSSL.Application.Abstractions;

/// <summary>Encrypts/decrypts secret material at rest (internal vault provider). No plaintext in DB.</summary>
public interface ISecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string ciphertext);
}
