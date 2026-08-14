using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;

namespace RemoteSSL.Runner;

/// <summary>Whatever fields the credential type needs; mirrors the control plane's SecretMaterial.</summary>
public sealed record RunnerSecret(
    string? Password = null, string? PrivateKeyPem = null, string? SshCertificate = null,
    string? Realm = null, string? Token = null, string? ClientId = null, string? ClientSecret = null,
    string? TokenEndpoint = null, string? Pkcs12Base64 = null, string? Pkcs12Password = null);

/// <summary>
/// Runner-direct secret retrieval (design doc §7.3, ADR-003). When the control plane answers a
/// credential request with a reference instead of a value, the runner fetches the secret itself
/// with its own provider credentials — so the plaintext exists only on the machine that is about
/// to use it, and never in the control plane's memory or logs.
/// </summary>
public class RunnerSecretResolver(IConfiguration config, IHttpClientFactory httpFactory)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>True when this runner is configured to reach the provider behind an identifier.</summary>
    public bool CanResolve(string provider) => provider switch
    {
        "HashiCorpVault" => !string.IsNullOrWhiteSpace(config["Vault:Addr"]) && !string.IsNullOrWhiteSpace(config["Vault:Token"]),
        "CyberArk" => !string.IsNullOrWhiteSpace(config["CyberArk:BaseUrl"]) && !string.IsNullOrWhiteSpace(config["CyberArk:AppId"]),
        "AzureKeyVault" => !string.IsNullOrWhiteSpace(config["AzureKeyVault:TenantId"]) && !string.IsNullOrWhiteSpace(config["AzureKeyVault:ClientId"]),
        _ => false
    };

    public async Task<RunnerSecret> ResolveAsync(string provider, string identifier, CancellationToken ct) =>
        provider switch
        {
            "HashiCorpVault" => await ReadVaultAsync(identifier, ct),
            "CyberArk" => await ReadCyberArkAsync(identifier, ct),
            "AzureKeyVault" => await ReadAzureAsync(identifier, ct),
            _ => throw new InvalidOperationException($"This runner cannot read secrets from '{provider}'.")
        };

    private async Task<RunnerSecret> ReadVaultAsync(string identifier, CancellationToken ct)
    {
        var (mount, path) = Split(identifier, "vault://");
        var http = httpFactory.CreateClient("runner-vault");
        http.BaseAddress = new Uri(config["Vault:Addr"]!.TrimEnd('/') + "/");
        http.DefaultRequestHeaders.Remove("X-Vault-Token");
        http.DefaultRequestHeaders.Add("X-Vault-Token", config["Vault:Token"]!);

        using var response = await http.GetAsync($"v1/{mount}/data/{path}", ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        var data = body.GetProperty("data").GetProperty("data");
        return new RunnerSecret(
            Password: Text(data, "password"),
            PrivateKeyPem: Text(data, "privateKey"),
            SshCertificate: Text(data, "sshCertificate"),
            Token: Text(data, "token"));
    }

    private async Task<RunnerSecret> ReadCyberArkAsync(string identifier, CancellationToken ct)
    {
        var (safe, objectName) = Split(identifier, "cyberark://");
        var http = httpFactory.CreateClient("runner-cyberark");
        http.BaseAddress = new Uri(config["CyberArk:BaseUrl"]!.TrimEnd('/') + "/");

        var query = $"AppID={HttpUtility.UrlEncode(config["CyberArk:AppId"])}"
                    + $"&Safe={HttpUtility.UrlEncode(safe)}&Object={HttpUtility.UrlEncode(objectName)}";
        using var response = await http.GetAsync($"AIMWebService/api/Accounts?{query}", ct);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        return new RunnerSecret(Password: Text(body, "Content"), PrivateKeyPem: Text(body, "PrivateKey"));
    }

    private async Task<RunnerSecret> ReadAzureAsync(string identifier, CancellationToken ct)
    {
        var (vault, secretName) = Split(identifier, "azurekv://");
        var http = httpFactory.CreateClient("runner-azure");

        using var tokenBody = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = config["AzureKeyVault:ClientId"]!,
            ["client_secret"] = config["AzureKeyVault:ClientSecret"] ?? string.Empty,
            ["scope"] = "https://vault.azure.net/.default",
            ["grant_type"] = "client_credentials"
        });
        using var tokenResponse = await http.PostAsync(
            $"https://login.microsoftonline.com/{config["AzureKeyVault:TenantId"]}/oauth2/v2.0/token", tokenBody, ct);
        tokenResponse.EnsureSuccessStatusCode();
        var token = (await tokenResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct))
            .GetProperty("access_token").GetString();

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://{vault}.vault.azure.net/secrets/{Uri.EscapeDataString(secretName)}?api-version=7.4");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var value = (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct))
            .GetProperty("value").GetString();

        if (value is not null && value.TrimStart().StartsWith('{'))
        {
            try { return JsonSerializer.Deserialize<RunnerSecret>(value, Json) ?? new RunnerSecret(); }
            catch (JsonException) { /* a plain password that happens to start with a brace */ }
        }
        return new RunnerSecret(Password: value);
    }

    private static (string Container, string Name) Split(string identifier, string scheme)
    {
        var path = identifier.Replace(scheme, string.Empty, StringComparison.OrdinalIgnoreCase).Trim('/');
        var slash = path.IndexOf('/');
        if (slash < 0) throw new ArgumentException($"Invalid secret reference '{identifier}'.");
        return (path[..slash], path[(slash + 1)..]);
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
