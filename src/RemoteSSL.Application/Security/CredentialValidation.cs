using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Application.Security;

/// <summary>
/// Minimum secret fields per credential type (design doc §7.2). Catching a half-filled credential
/// at creation beats discovering it when a deployment is already halfway through a target.
/// </summary>
public static class CredentialValidation
{
    /// <summary>Returns the problem with this material, or null when it is usable.</summary>
    public static string? Validate(CredentialType type, SecretMaterial m) => type switch
    {
        CredentialType.UsernamePassword when string.IsNullOrEmpty(m.Password) =>
            "A username/password credential needs a password.",
        CredentialType.SshPrivateKey when string.IsNullOrEmpty(m.PrivateKeyPem) =>
            "An SSH key credential needs a private key.",
        CredentialType.SshCertificate when string.IsNullOrEmpty(m.PrivateKeyPem) || string.IsNullOrEmpty(m.SshCertificate) =>
            "An SSH certificate credential needs both the private key and the signed certificate.",
        CredentialType.KerberosServiceAccount when string.IsNullOrEmpty(m.Password) || string.IsNullOrEmpty(m.Realm) =>
            "A Kerberos service account needs a password and a realm.",
        CredentialType.ApiKeySecret or CredentialType.BearerToken when string.IsNullOrEmpty(m.Token) =>
            "An API key / bearer token credential needs a token.",
        CredentialType.OAuthClientCredentials when string.IsNullOrEmpty(m.ClientId)
                                                   || string.IsNullOrEmpty(m.ClientSecret)
                                                   || string.IsNullOrEmpty(m.TokenEndpoint) =>
            "OAuth client credentials need a client id, client secret and token endpoint.",
        CredentialType.ClientCertificate when string.IsNullOrEmpty(m.Pkcs12Base64) =>
            "A client certificate credential needs a base64 PKCS#12 bundle.",
        CredentialType.ExternalSecretReference =>
            "An external secret reference belongs to an external provider, not the internal vault.",
        _ => null
    };
}
