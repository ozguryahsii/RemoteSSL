using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Infrastructure.Security;

/// <summary>
/// Cloud HSM key references (design doc §16.3), implemented against Azure Key Vault / Managed HSM
/// keys. The key itself is created and governed in the cloud service; RemoteSSL only references it
/// by URI ("azurekms://&lt;vault&gt;/&lt;key&gt;") and asks the service to sign. As with PKCS#11,
/// the private half is never in this process.
/// </summary>
public class CloudKmsKeyProvider(IHttpClientFactory httpFactory, IConfiguration configuration) : IKeyProvider
{
    private const string Scope = "https://vault.azure.net/.default";

    public KeyProviderKind Kind => KeyProviderKind.CloudKms;

    public bool Enabled => !string.IsNullOrWhiteSpace(configuration["AzureKeyVault:TenantId"])
                           && !string.IsNullOrWhiteSpace(configuration["AzureKeyVault:ClientId"]);

    /// <summary>
    /// Creates the key inside the vault. RSA-HSM keeps it in the HSM backing store, which is what
    /// makes this a cloud HSM reference rather than just a hosted software key.
    /// </summary>
    public async Task<GeneratedKey> GenerateAsync(KeySpec spec, CancellationToken ct)
    {
        EnsureEnabled();
        if (spec.Exportable)
            throw new InvalidOperationException(
                "Cloud HSM keys are created non-exportable; request a software key if the private half must be exportable.");

        var vault = configuration["AzureKeyVault:KeyVaultName"]
                    ?? throw new InvalidOperationException("AzureKeyVault:KeyVaultName is not configured.");

        var response = await SendAsync(HttpMethod.Post,
            $"https://{vault}.vault.azure.net/keys/{Uri.EscapeDataString(spec.Label)}/create",
            JsonContent.Create(new
            {
                kty = "RSA-HSM",
                key_size = spec.SizeOrCurve < 2048 ? 2048 : spec.SizeOrCurve,
                key_ops = new[] { "sign", "verify" }
            }), ct);

        var jwk = response.GetProperty("key");
        return new GeneratedKey($"azurekms://{vault}/{spec.Label}", PublicPemFromJwk(jwk), null);
    }

    public async Task<string> CreateCsrPemAsync(string reference, string subject, IReadOnlyList<string> sans,
        string? privateKeyPem, CancellationToken ct)
    {
        EnsureEnabled();
        var (vault, keyName) = Split(reference);
        var jwk = (await SendAsync(HttpMethod.Get,
            $"https://{vault}.vault.azure.net/keys/{Uri.EscapeDataString(keyName)}", null, ct)).GetProperty("key");
        var keyId = jwk.GetProperty("kid").GetString()!;

        using var rsa = new CloudKmsRsa(this, keyId, ParametersFromJwk(jwk));
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SoftwareKeyProvider.AddSans(request, sans);
        return request.CreateSigningRequestPem();
    }

    public async Task DestroyAsync(string reference, CancellationToken ct)
    {
        EnsureEnabled();
        var (vault, keyName) = Split(reference);
        await SendAsync(HttpMethod.Delete,
            $"https://{vault}.vault.azure.net/keys/{Uri.EscapeDataString(keyName)}", null, ct);
    }

    private void EnsureEnabled()
    {
        if (!Enabled)
            throw new InvalidOperationException(
                "Cloud HSM is not configured (AzureKeyVault:TenantId, ClientId, ClientSecret).");
    }

    private async Task<JsonElement> SendAsync(HttpMethod method, string url, HttpContent? content, CancellationToken ct)
    {
        var apiVersion = configuration["AzureKeyVault:ApiVersion"] ?? "7.4";
        var http = httpFactory.CreateClient("azure-kms");
        using var request = new HttpRequestMessage(method,
            url + (url.Contains('?') ? "&" : "?") + $"api-version={apiVersion}") { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await AcquireTokenAsync(ct));

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    private async Task<string> AcquireTokenAsync(CancellationToken ct)
    {
        var http = httpFactory.CreateClient("azure-kms-token");
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = configuration["AzureKeyVault:ClientId"]!,
            ["client_secret"] = configuration["AzureKeyVault:ClientSecret"] ?? string.Empty,
            ["scope"] = Scope,
            ["grant_type"] = "client_credentials"
        });

        using var response = await http.PostAsync(
            $"https://login.microsoftonline.com/{configuration["AzureKeyVault:TenantId"]}/oauth2/v2.0/token",
            content, ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        return body.GetProperty("access_token").GetString()
               ?? throw new InvalidOperationException("Azure token response carried no access_token.");
    }

    /// <summary>Asks the vault to sign a digest with the referenced key.</summary>
    private async Task<byte[]> SignAsync(string keyId, byte[] hash, string algorithm, CancellationToken ct)
    {
        var body = await SendAsync(HttpMethod.Post, $"{keyId.TrimEnd('/')}/sign",
            JsonContent.Create(new { alg = algorithm, value = Base64Url(hash) }), ct);
        return FromBase64Url(body.GetProperty("value").GetString()!);
    }

    private static (string Vault, string Key) Split(string reference)
    {
        var path = reference.Replace("azurekms://", string.Empty, StringComparison.OrdinalIgnoreCase).Trim('/');
        var slash = path.IndexOf('/');
        if (slash < 0)
            throw new ArgumentException($"Invalid cloud key reference '{reference}'; expected azurekms://<vault>/<key>.");
        return (path[..slash], path[(slash + 1)..]);
    }

    private static RSAParameters ParametersFromJwk(JsonElement jwk) => new()
    {
        Modulus = FromBase64Url(jwk.GetProperty("n").GetString()!),
        Exponent = FromBase64Url(jwk.GetProperty("e").GetString()!)
    };

    private static string PublicPemFromJwk(JsonElement jwk)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(ParametersFromJwk(jwk));
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }

    /// <summary>An <see cref="RSA"/> that delegates signing to the vault; nothing else is possible.</summary>
    private sealed class CloudKmsRsa(CloudKmsKeyProvider provider, string keyId, RSAParameters publicParameters) : RSA
    {
        public override RSAParameters ExportParameters(bool includePrivateParameters) =>
            includePrivateParameters
                ? throw new CryptographicException("A cloud HSM private key cannot be exported.")
                : publicParameters;

        public override void ImportParameters(RSAParameters parameters) =>
            throw new NotSupportedException("A cloud HSM key is created in the vault, not imported.");

        public override int KeySize => (publicParameters.Modulus?.Length ?? 0) * 8;

        public override KeySizes[] LegalKeySizes => [new KeySizes(KeySize, KeySize, 0)];

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (padding != RSASignaturePadding.Pkcs1)
                throw new NotSupportedException("The cloud HSM signer supports PKCS#1 v1.5 padding only.");

            var alg = hashAlgorithm.Name switch
            {
                nameof(HashAlgorithmName.SHA384) => "RS384",
                nameof(HashAlgorithmName.SHA512) => "RS512",
                _ => "RS256"
            };
            // CertificateRequest signs synchronously; this is the one place the async call is
            // blocked on, and it is a single outbound request.
            return provider.SignAsync(keyId, hash, alg, CancellationToken.None).GetAwaiter().GetResult();
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
    }
}
