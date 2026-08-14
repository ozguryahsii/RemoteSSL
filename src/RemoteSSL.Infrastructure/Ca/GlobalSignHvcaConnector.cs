using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Infrastructure.Ca;

public sealed class HvcaConfig
{
    public string BaseUrl { get; set; } = "https://emea.api.hvca.globalsign.com:8443/v2";
    public string ApiKey { get; set; } = string.Empty;
    public string ApiSecret { get; set; } = string.Empty;
    /// <summary>mTLS client certificate (PFX, base64) + password, as required by HVCA.</summary>
    public string? ClientPfxBase64 { get; set; }
    public string? ClientPfxPassword { get; set; }
}

/// <summary>
/// GlobalSign HVCA (Atlas) connector: mTLS + POST /login → short-lived JWT,
/// validation policy as profile, POST /certificates with PKCS#10, GET for
/// retrieval, DELETE for revocation. Re-authenticates transparently on 401.
/// Endpoint mapping documented in docs/ca-connector.md; to be validated against a
/// live GlobalSign account.
/// </summary>
public class GlobalSignHvcaConnector(HvcaConfig config, IHttpClientFactory? httpFactory = null) : ICertificateAuthorityConnector
{
    public string ConnectorType => "globalsign-hvca";
    private string? _token;

    private HttpClient CreateClient()
    {
        HttpClient http;
        if (config.ClientPfxBase64 is not null)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(new X509Certificate2(
                Convert.FromBase64String(config.ClientPfxBase64), config.ClientPfxPassword));
            http = new HttpClient(handler);
        }
        else
        {
            http = httpFactory?.CreateClient("hvca") ?? new HttpClient();
        }
        http.BaseAddress = new Uri(config.BaseUrl.TrimEnd('/') + "/");
        http.Timeout = TimeSpan.FromSeconds(30);
        if (_token is not null)
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        return http;
    }

    private async Task LoginAsync(CancellationToken ct)
    {
        using var http = CreateClient();
        var res = await http.PostAsJsonAsync("login", new { api_key = config.ApiKey, api_secret = config.ApiSecret }, ct);
        res.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        _token = doc.RootElement.GetProperty("access_token").GetString();
    }

    private async Task<HttpResponseMessage> SendAsync(Func<HttpClient, Task<HttpResponseMessage>> call, CancellationToken ct)
    {
        if (_token is null) await LoginAsync(ct);
        using (var http = CreateClient())
        {
            var res = await call(http);
            if (res.StatusCode != System.Net.HttpStatusCode.Unauthorized) return res;
        }
        await LoginAsync(ct); // token expired — re-login once
        using var retry = CreateClient();
        return await call(retry);
    }

    public async Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct)
    {
        try
        {
            await LoginAsync(ct);
            return new CaConnectionResult(true);
        }
        catch (Exception ex)
        {
            return new CaConnectionResult(false, ex.Message);
        }
    }

    public async Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct)
    {
        var res = await SendAsync(h => h.GetAsync("validationpolicy", ct), ct);
        res.EnsureSuccessStatusCode();
        var raw = await res.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;

        var algos = new List<string>();
        int maxDays = 397;
        bool wildcard = false;
        if (root.TryGetProperty("public_key", out var pk))
        {
            if (pk.TryGetProperty("key_type", out var kt)) algos.Add(kt.GetString() ?? "RSA");
        }
        if (algos.Count == 0) algos.AddRange(["RSA", "EC"]);
        if (root.TryGetProperty("validity", out var val) && val.TryGetProperty("secondsmax", out var sm))
            maxDays = (int)(sm.GetInt64() / 86400);
        if (root.TryGetProperty("san", out var san) && san.TryGetProperty("dns_names", out var dns)
            && dns.TryGetProperty("static", out _))
            wildcard = raw.Contains("*.");

        return [new CaProfile("default", "HVCA Validation Policy", algos, maxDays, wildcard, raw)];
    }

    public async Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId,
        IReadOnlyDictionary<string, string> metadata, CancellationToken ct)
    {
        var body = new Dictionary<string, object> { ["public_key"] = csrPem, ["public_key_type"] = "csr" };
        if (metadata.TryGetValue("validity_seconds", out var vs) && long.TryParse(vs, out var secs))
            body["validity"] = new { not_after = DateTimeOffset.UtcNow.AddSeconds(secs).ToUnixTimeSeconds() };

        var res = await SendAsync(h => h.PostAsJsonAsync("certificates", body, ct), ct);
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException($"HVCA submit failed {(int)res.StatusCode}: {await res.Content.ReadAsStringAsync(ct)}");
        // HVCA returns the certificate identifier in the Location header.
        var location = res.Headers.Location?.ToString() ?? throw new InvalidOperationException("HVCA response missing Location");
        var id = location.TrimEnd('/').Split('/').Last();
        return new CaRequestRef(ConnectorType, id);
    }

    public async Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct)
    {
        var res = await SendAsync(h => h.GetAsync($"certificates/{request.ProviderRequestId}", ct), ct);
        if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
            return new CaRequestStatus(CaRequestState.Failed, "certificate not found");
        if (!res.IsSuccessStatusCode)
            return new CaRequestStatus(CaRequestState.Pending, $"HTTP {(int)res.StatusCode}");
        return new CaRequestStatus(CaRequestState.Issued);
    }

    public async Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct)
    {
        var res = await SendAsync(h => h.GetAsync($"certificates/{request.ProviderRequestId}", ct), ct);
        res.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
        var pem = doc.RootElement.GetProperty("certificate").GetString()!;

        var chainRes = await SendAsync(h => h.GetAsync("trustchain", ct), ct);
        var chain = "";
        if (chainRes.IsSuccessStatusCode)
        {
            using var cd = JsonDocument.Parse(await chainRes.Content.ReadAsStringAsync(ct));
            chain = string.Join('\n', cd.RootElement.EnumerateArray().Select(e => e.GetString()));
        }

        using var cert = X509Certificate2.CreateFromPem(pem);
        return new IssuedCertificate(pem, chain, cert.SerialNumber);
    }

    public Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId, CancellationToken ct)
        => SubmitRequestAsync(csrPem, profileId, new Dictionary<string, string>(), ct); // HVCA renewal = new issuance

    public async Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct)
    {
        var res = await SendAsync(h => h.DeleteAsync($"certificates/{certificateSerial}", ct), ct);
        res.EnsureSuccessStatusCode();
    }

    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method, CancellationToken ct)
        => Task.FromResult<DomainValidationChallenge?>(null); // HVCA domain claims arrive in a later iteration
}

/// <summary>Manual/offline CA: CSR is produced, the request parks until the operator uploads the issued certificate.</summary>
public class ManualCaConnector : ICertificateAuthorityConnector
{
    public string ConnectorType => "manual";
    public Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct) => Task.FromResult(new CaConnectionResult(true));
    public Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<CaProfile>>([new CaProfile("manual", "Manual / Offline CA", ["RSA", "EC"], 825, true, "{}")]);
    public Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId, IReadOnlyDictionary<string, string> metadata, CancellationToken ct) =>
        Task.FromResult(new CaRequestRef(ConnectorType, Guid.NewGuid().ToString("N")));
    public Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct) =>
        Task.FromResult(new CaRequestStatus(CaRequestState.ValidationRequired, "waiting for operator to upload the signed certificate"));
    public Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct) =>
        throw new InvalidOperationException("Manual CA: certificate must be uploaded by the operator");
    public Task<CaRequestRef> RenewAsync(string serial, string csrPem, string profileId, CancellationToken ct) =>
        SubmitRequestAsync(csrPem, profileId, new Dictionary<string, string>(), ct);
    public Task RevokeAsync(string serial, RevocationReason reason, CancellationToken ct) =>
        throw new InvalidOperationException("Manual CA: revoke via the CA's own interface");
    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method, CancellationToken ct) =>
        Task.FromResult<DomainValidationChallenge?>(null);
}

/// <summary>Resolves connector instances from stored (encrypted) configuration.</summary>
public class CaConnectorFactory(RemoteSSL.Application.Abstractions.ISecretProtector protector, IHttpClientFactory httpFactory)
{
    public ICertificateAuthorityConnector Create(string connectorType, string encryptedConfigJson)
    {
        var json = string.IsNullOrEmpty(encryptedConfigJson) ? "{}" : protector.Unprotect(encryptedConfigJson);
        return connectorType switch
        {
            "manual" => new ManualCaConnector(),
            "globalsign-hvca" => new GlobalSignHvcaConnector(Config<HvcaConfig>(json), httpFactory),
            "acme" => new AcmeConnector(Config<AcmeConfig>(json), httpFactory),
            "adcs" => new AdcsConnector(Config<AdcsConfig>(json), httpFactory),
            "digicert" => new DigiCertConnector(Config<RestCaConfig>(json), httpFactory),
            "sectigo" => new GenericRestCaConnector(
                Config<RestCaConfig>(json), GenericRestCaConfig.Sectigo(), httpFactory),
            // Anything else that speaks "post a CSR, poll an id, download a PEM"; the endpoint
            // paths live in the connector's own configuration (§18.3).
            "rest-ca" => new GenericRestCaConnector(
                Config<RestCaConfig>(json), Config<GenericRestCaConfig>(json), httpFactory),
            _ => throw new NotSupportedException($"Unknown CA connector type '{connectorType}'")
        };
    }

    private static T Config<T>(string json) where T : new() =>
        JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? new T();

    /// <summary>The connector types this build can create, for the CA integrations screen.</summary>
    public static IReadOnlyList<string> SupportedTypes =>
        ["manual", "globalsign-hvca", "acme", "adcs", "digicert", "sectigo", "rest-ca"];
}
