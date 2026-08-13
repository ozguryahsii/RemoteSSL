using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace RemoteSSL.Infrastructure.Security;

/// <summary>
/// HashiCorp Vault KV v2 client (design doc §7.2 external secret reference).
/// SecretIdentifier format: "vault://&lt;mount&gt;/&lt;path&gt;" — e.g. "vault://secret/prod/web01".
/// Expects the secret's data to carry "password" and/or "privateKey" fields.
/// Vault address + token come from configuration (Vault:Addr, Vault:Token) — the
/// token itself should be injected via environment, not committed.
/// </summary>
public class VaultSecretClient(IHttpClientFactory httpFactory, IConfiguration config)
{
    public async Task<(string? Password, string? PrivateKeyPem)> ReadAsync(string secretIdentifier, CancellationToken ct)
    {
        var addr = config["Vault:Addr"] ?? throw new InvalidOperationException("Vault:Addr not configured");
        var token = config["Vault:Token"] ?? throw new InvalidOperationException("Vault:Token not configured");

        var path = secretIdentifier.Replace("vault://", "").TrimStart('/');
        var slash = path.IndexOf('/');
        if (slash < 0) throw new ArgumentException($"Invalid vault reference '{secretIdentifier}'");
        var mount = path[..slash];
        var secretPath = path[(slash + 1)..];

        using var http = httpFactory.CreateClient("vault");
        http.BaseAddress = new Uri(addr.TrimEnd('/') + "/");
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);
        http.Timeout = TimeSpan.FromSeconds(15);

        var res = await http.GetAsync($"v1/{mount}/data/{secretPath}", ct);
        res.EnsureSuccessStatusCode();
        var body = await res.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        var data = body.GetProperty("data").GetProperty("data");
        return (
            data.TryGetProperty("password", out var pw) ? pw.GetString() : null,
            data.TryGetProperty("privateKey", out var pk) ? pk.GetString() : null);
    }
}
