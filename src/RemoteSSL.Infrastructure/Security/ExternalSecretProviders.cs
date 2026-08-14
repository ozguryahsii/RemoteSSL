using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.Configuration;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Domain;

namespace RemoteSSL.Infrastructure.Security;

/// <summary>
/// HashiCorp Vault KV v2 (§7.2). Identifier: "vault://&lt;mount&gt;/&lt;path&gt;".
/// </summary>
public class VaultSecretProvider(VaultSecretClient client, IConfiguration configuration) : ISecretProvider
{
    public SecretProviderType Provider => SecretProviderType.HashiCorpVault;
    public bool Enabled => !string.IsNullOrWhiteSpace(configuration["Vault:Addr"]);

    public async Task<SecretMaterial> ReadAsync(string secretIdentifier, CancellationToken ct)
    {
        var (password, key) = await client.ReadAsync(secretIdentifier, ct);
        return new SecretMaterial(Password: password, PrivateKeyPem: key);
    }
}

/// <summary>
/// CyberArk Central Credential Provider (§7.2). Identifier:
/// "cyberark://&lt;safe&gt;/&lt;object&gt;" — the AppID comes from configuration, and the CCP
/// itself authorises the request based on the calling application and machine, which is why no
/// password is sent from here.
/// </summary>
public class CyberArkSecretProvider(IHttpClientFactory httpFactory, IConfiguration configuration) : ISecretProvider
{
    public SecretProviderType Provider => SecretProviderType.CyberArk;
    public bool Enabled => !string.IsNullOrWhiteSpace(configuration["CyberArk:BaseUrl"])
                           && !string.IsNullOrWhiteSpace(configuration["CyberArk:AppId"]);

    public async Task<SecretMaterial> ReadAsync(string secretIdentifier, CancellationToken ct)
    {
        if (!Enabled) throw new InvalidOperationException("CyberArk is not configured (CyberArk:BaseUrl, CyberArk:AppId).");

        var (safe, objectName) = Split(secretIdentifier);
        var http = httpFactory.CreateClient("cyberark");
        http.BaseAddress = new Uri(configuration["CyberArk:BaseUrl"]!.TrimEnd('/') + "/");
        http.Timeout = TimeSpan.FromSeconds(configuration.GetValue("CyberArk:TimeoutSeconds", 15));

        var query = $"AppID={HttpUtility.UrlEncode(configuration["CyberArk:AppId"])}"
                    + $"&Safe={HttpUtility.UrlEncode(safe)}"
                    + $"&Object={HttpUtility.UrlEncode(objectName)}";

        var response = await http.GetAsync($"AIMWebService/api/Accounts?{query}", ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);

        return new SecretMaterial(
            Password: Read(body, "Content"),
            // CCP returns extra properties for key-bearing accounts under their own names.
            PrivateKeyPem: Read(body, "PrivateKey"),
            Token: Read(body, "Token"));
    }

    private static (string Safe, string Object) Split(string identifier)
    {
        var path = identifier.Replace("cyberark://", string.Empty, StringComparison.OrdinalIgnoreCase).Trim('/');
        var slash = path.IndexOf('/');
        if (slash < 0)
            throw new ArgumentException($"Invalid CyberArk reference '{identifier}'; expected cyberark://<safe>/<object>.");
        return (path[..slash], path[(slash + 1)..]);
    }

    private static string? Read(JsonElement body, string property) =>
        body.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}

/// <summary>
/// Azure Key Vault secrets (§7.2). Identifier: "azurekv://&lt;vault-name&gt;/&lt;secret-name&gt;".
/// Authenticates with client credentials when configured, which keeps the integration usable
/// outside Azure; inside Azure a managed identity endpoint can supply the same token.
/// </summary>
public class AzureKeyVaultSecretProvider(IHttpClientFactory httpFactory, IConfiguration configuration) : ISecretProvider
{
    private const string Scope = "https://vault.azure.net/.default";

    public SecretProviderType Provider => SecretProviderType.AzureKeyVault;
    public bool Enabled => !string.IsNullOrWhiteSpace(configuration["AzureKeyVault:TenantId"])
                           && !string.IsNullOrWhiteSpace(configuration["AzureKeyVault:ClientId"]);

    public async Task<SecretMaterial> ReadAsync(string secretIdentifier, CancellationToken ct)
    {
        if (!Enabled)
            throw new InvalidOperationException(
                "Azure Key Vault is not configured (AzureKeyVault:TenantId, ClientId, ClientSecret).");

        var (vaultName, secretName) = Split(secretIdentifier);
        var token = await AcquireTokenAsync(ct);

        var http = httpFactory.CreateClient("azure-key-vault");
        http.Timeout = TimeSpan.FromSeconds(configuration.GetValue("AzureKeyVault:TimeoutSeconds", 15));
        var apiVersion = configuration["AzureKeyVault:ApiVersion"] ?? "7.4";

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://{vaultName}.vault.azure.net/secrets/{Uri.EscapeDataString(secretName)}?api-version={apiVersion}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        var value = body.TryGetProperty("value", out var v) ? v.GetString() : null;

        // A Key Vault secret is a single string; a JSON document lets one entry carry both a
        // password and a key, which is how multi-field credentials are stored in practice.
        if (value is not null && value.TrimStart().StartsWith('{'))
        {
            try
            {
                var structured = JsonSerializer.Deserialize<SecretMaterial>(value,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web));
                if (structured is not null) return structured;
            }
            catch (JsonException)
            {
                // Not a structured secret after all; fall through and treat it as a password.
            }
        }

        return new SecretMaterial(Password: value);
    }

    private async Task<string> AcquireTokenAsync(CancellationToken ct)
    {
        var http = httpFactory.CreateClient("azure-key-vault-token");
        var tenant = configuration["AzureKeyVault:TenantId"];
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = configuration["AzureKeyVault:ClientId"]!,
            ["client_secret"] = configuration["AzureKeyVault:ClientSecret"] ?? string.Empty,
            ["scope"] = Scope,
            ["grant_type"] = "client_credentials"
        });

        using var response = await http.PostAsync(
            $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", content, ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        return body.GetProperty("access_token").GetString()
               ?? throw new InvalidOperationException("Azure token response carried no access_token.");
    }

    private static (string Vault, string Secret) Split(string identifier)
    {
        var path = identifier.Replace("azurekv://", string.Empty, StringComparison.OrdinalIgnoreCase).Trim('/');
        var slash = path.IndexOf('/');
        if (slash < 0)
            throw new ArgumentException($"Invalid Key Vault reference '{identifier}'; expected azurekv://<vault>/<secret>.");
        return (path[..slash], path[(slash + 1)..]);
    }
}
