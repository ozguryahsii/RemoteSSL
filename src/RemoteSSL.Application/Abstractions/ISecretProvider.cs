using RemoteSSL.Domain;

namespace RemoteSSL.Application.Abstractions;

/// <summary>
/// Secret material for the credential types of design doc §7.2. Only the fields a given
/// credential type needs are populated; nothing here is ever logged or returned to a UI.
/// </summary>
public sealed record SecretMaterial(
    string? Password = null,
    string? PrivateKeyPem = null,
    /// <summary>Signed SSH certificate accompanying the private key (§7.2 SSH certificate).</summary>
    string? SshCertificate = null,
    /// <summary>Kerberos/WinRM service account realm, when the account is domain-joined.</summary>
    string? Realm = null,
    /// <summary>API key / OAuth client secret / bearer token, depending on the credential type.</summary>
    string? Token = null,
    string? ClientId = null,
    string? ClientSecret = null,
    string? TokenEndpoint = null,
    /// <summary>Base64 PKCS#12 for client-certificate credentials, with its password.</summary>
    string? Pkcs12Base64 = null,
    string? Pkcs12Password = null);

/// <summary>
/// A source of secrets (§7.2). Implementations exist for the internal encrypted store and for
/// external providers; the broker picks one per credential so no adapter needs to know where a
/// secret lives.
/// </summary>
public interface ISecretProvider
{
    SecretProviderType Provider { get; }
    /// <summary>False when the provider is compiled in but not configured; it is then never used.</summary>
    bool Enabled { get; }
    Task<SecretMaterial> ReadAsync(string secretIdentifier, CancellationToken ct);
}
