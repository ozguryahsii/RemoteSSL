using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Infrastructure.Ca;

public sealed class AdcsConfig
{
    /// <summary>Base URL of the certsrv web enrollment site, e.g. https://ca01.corp/certsrv.</summary>
    public string BaseUrl { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    /// <summary>"ntlm" (default), "negotiate" or "basic" — how the enrollment site authenticates.</summary>
    public string AuthScheme { get; set; } = "ntlm";
    /// <summary>Certificate templates offered as profiles; certsrv has no API to enumerate them.</summary>
    public List<string> Templates { get; set; } = ["WebServer"];
    public int MaxValidityDays { get; set; } = 730;
}

/// <summary>
/// Microsoft AD CS via the certsrv web enrollment interface (design doc §18.3).
///
/// AD CS has no REST API; certsrv is the supported remote surface, and it is an HTML form. Two
/// things follow. Submission posts the CSR to certfnsh.asp and the request id comes back in the
/// redirect, so it is scraped rather than parsed from JSON. And issuance is usually immediate for
/// an auto-enroll template but pending for one that requires manager approval — which is the
/// difference this connector reports as ValidationRequired.
/// </summary>
public class AdcsConnector(AdcsConfig config, IHttpClientFactory? httpFactory = null) : ICertificateAuthorityConnector
{
    // httpFactory is accepted for a uniform factory signature; AD CS needs its own handler for
    // Windows authentication, so the shared client cannot be used here.
    private readonly IHttpClientFactory? _unusedFactory = httpFactory;

    public string ConnectorType => "adcs";

    private HttpClient Client()
    {
        var credentials = new NetworkCredential(config.Username, config.Password);
        var handler = new HttpClientHandler
        {
            // certsrv is domain-authenticated; basic auth only works where IIS was configured for it.
            Credentials = config.AuthScheme.Equals("basic", StringComparison.OrdinalIgnoreCase)
                ? credentials
                : new CredentialCache
                {
                    { new Uri(config.BaseUrl), config.AuthScheme.Equals("negotiate", StringComparison.OrdinalIgnoreCase)
                        ? "Negotiate" : "NTLM", credentials }
                },
            PreAuthenticate = true
        };
        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri(config.BaseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(60)
        };
        if (config.AuthScheme.Equals("basic", StringComparison.OrdinalIgnoreCase))
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{config.Username}:{config.Password}")));
        return http;
    }

    public async Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct)
    {
        try
        {
            using var http = Client();
            using var response = await http.GetAsync("certsrv/", ct);
            return response.IsSuccessStatusCode
                ? new CaConnectionResult(true)
                : new CaConnectionResult(false, $"certsrv returned {(int)response.StatusCode}");
        }
        catch (Exception ex)
        {
            return new CaConnectionResult(false, ex.Message);
        }
    }

    /// <summary>
    /// Templates come from configuration: certsrv does not expose the list, and reading it from
    /// Active Directory would need an LDAP path this connector deliberately does not take.
    /// </summary>
    public Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<CaProfile>>(config.Templates
            .Select(t => new CaProfile(t, $"AD CS template — {t}", ["RSA", "EC"],
                config.MaxValidityDays, true, $$"""{"template":"{{t}}"}"""))
            .ToList());

    public async Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId,
        IReadOnlyDictionary<string, string> metadata, CancellationToken ct)
    {
        using var http = Client();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Mode"] = "newreq",
            ["CertRequest"] = csrPem,
            ["CertAttrib"] = $"CertificateTemplate:{profileId}",
            ["TargetStoreFlags"] = "0",
            ["SaveCert"] = "yes",
            ["ThumbPrint"] = ""
        });

        using var response = await http.PostAsync("certsrv/certfnsh.asp", form, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"AD CS submission failed: {(int)response.StatusCode}");

        var requestId = ExtractRequestId(body)
                        ?? throw new InvalidOperationException(
                            $"AD CS did not return a request id. {DenialReason(body)}");
        return new CaRequestRef(ConnectorType, requestId);
    }

    /// <summary>
    /// certsrv puts the request id in the link to the retrieval page. It is the only machine
    /// readable thing on that page, which is why this is a regex over HTML and not a parse.
    /// </summary>
    public static string? ExtractRequestId(string html)
    {
        var match = Regex.Match(html, @"certnew\.cer\?ReqID=(?<id>\d+)", RegexOptions.IgnoreCase);
        if (match.Success) return match.Groups["id"].Value;
        match = Regex.Match(html, @"certckpn\.asp\?ReqID=(?<id>\d+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["id"].Value : null;
    }

    /// <summary>The denial text certsrv shows, so a rejected request says why rather than "failed".</summary>
    public static string DenialReason(string html)
    {
        var match = Regex.Match(html, @"(?:Denied by Policy Module|The request was denied)[^<]*",
            RegexOptions.IgnoreCase);
        if (match.Success) return match.Value.Trim();
        return html.Contains("taken under submission", StringComparison.OrdinalIgnoreCase)
            ? "The request is pending a certificate manager's approval."
            : "No request id was present in the response.";
    }

    public async Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct)
    {
        using var http = Client();
        using var response = await http.GetAsync($"certsrv/certnew.cer?ReqID={request.ProviderRequestId}&Enc=b64", ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        if (body.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            return new CaRequestStatus(CaRequestState.Issued);
        if (body.Contains("under submission", StringComparison.OrdinalIgnoreCase))
            return new CaRequestStatus(CaRequestState.ValidationRequired,
                "waiting for a certificate manager to approve the request");
        if (body.Contains("denied", StringComparison.OrdinalIgnoreCase))
            return new CaRequestStatus(CaRequestState.Rejected, DenialReason(body));
        return new CaRequestStatus(CaRequestState.Pending);
    }

    public async Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct)
    {
        using var http = Client();
        var leaf = await http.GetStringAsync(
            $"certsrv/certnew.cer?ReqID={request.ProviderRequestId}&Enc=b64", ct);
        if (!leaf.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            throw new InvalidOperationException("AD CS has not issued this request yet.");

        // The chain comes from the CA's own certificate page; it is a PKCS#7 the platform's
        // format engine already knows how to unpack.
        var chain = string.Empty;
        try
        {
            chain = await http.GetStringAsync("certsrv/certnew.p7b?ReqID=CACert&Renewal=0&Enc=b64", ct);
        }
        catch (HttpRequestException)
        {
            // A CA that does not publish its chain here is not a failed issuance.
        }

        using var certificate = X509Certificate2.CreateFromPem(leaf);
        return new IssuedCertificate(leaf, chain, certificate.SerialNumber);
    }

    public Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId,
        CancellationToken ct) =>
        SubmitRequestAsync(csrPem, profileId, new Dictionary<string, string>(), ct);

    public Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct) =>
        // certsrv has no revocation surface; revocation is a certutil/MMC operation on the CA.
        throw new NotSupportedException(
            "AD CS revocation is not exposed by certsrv; revoke on the CA (certutil -revoke) and record it here.");

    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method,
        CancellationToken ct) =>
        // An internal CA validates by domain membership, not by proof of control.
        Task.FromResult<DomainValidationChallenge?>(null);
}

public sealed class RestCaConfig
{
    public string BaseUrl { get; set; } = string.Empty;
    /// <summary>Bearer token, or the vendor's own key header value.</summary>
    public string ApiKey { get; set; } = string.Empty;
    /// <summary>Header the key goes in. DigiCert uses X-DC-DEVKEY, Sectigo uses login/password.</summary>
    public string ApiKeyHeader { get; set; } = "Authorization";
    public string? OrganizationId { get; set; }
    /// <summary>Product/profile ids offered as profiles when the API cannot enumerate them.</summary>
    public List<string> Profiles { get; set; } = [];
    public int MaxValidityDays { get; set; } = 397;
}

/// <summary>
/// DigiCert CertCentral (design doc §18.3). Orders are placed against a product, and the order id
/// is the handle; certificates arrive after validation, which CertCentral tracks on the order.
/// </summary>
public class DigiCertConnector(RestCaConfig config, IHttpClientFactory? httpFactory = null) : ICertificateAuthorityConnector
{
    public string ConnectorType => "digicert";

    private HttpClient Client()
    {
        var http = httpFactory?.CreateClient("digicert") ?? new HttpClient();
        http.BaseAddress = new Uri((string.IsNullOrWhiteSpace(config.BaseUrl)
            ? "https://www.digicert.com/services/v2/" : config.BaseUrl.TrimEnd('/') + "/"));
        http.Timeout = TimeSpan.FromSeconds(60);
        http.DefaultRequestHeaders.Remove("X-DC-DEVKEY");
        http.DefaultRequestHeaders.Add("X-DC-DEVKEY", config.ApiKey);
        return http;
    }

    public async Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct)
    {
        try
        {
            using var http = Client();
            using var response = await http.GetAsync("user/me", ct);
            return response.IsSuccessStatusCode
                ? new CaConnectionResult(true)
                : new CaConnectionResult(false, $"CertCentral returned {(int)response.StatusCode}");
        }
        catch (Exception ex) { return new CaConnectionResult(false, ex.Message); }
    }

    public async Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct)
    {
        using var http = Client();
        using var response = await http.GetAsync("product", ct);
        if (!response.IsSuccessStatusCode)
            return config.Profiles.Select(Fallback).ToList();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
        if (!body.TryGetProperty("products", out var products))
            return config.Profiles.Select(Fallback).ToList();

        return products.EnumerateArray().Select(p => new CaProfile(
            p.GetProperty("name_id").GetString()!,
            p.TryGetProperty("name", out var n) ? n.GetString()! : p.GetProperty("name_id").GetString()!,
            ["RSA", "EC"],
            config.MaxValidityDays,
            p.TryGetProperty("allowed_ca_certs", out _),
            p.ToString())).ToList();
    }

    private CaProfile Fallback(string id) =>
        new(id, $"DigiCert — {id}", ["RSA", "EC"], config.MaxValidityDays, true, "{}");

    public async Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId,
        IReadOnlyDictionary<string, string> metadata, CancellationToken ct)
    {
        using var http = Client();
        var payload = new
        {
            certificate = new
            {
                common_name = metadata.GetValueOrDefault("commonName"),
                dns_names = metadata.GetValueOrDefault("sans")?.Split(',', StringSplitOptions.RemoveEmptyEntries),
                csr = csrPem,
                signature_hash = "sha256"
            },
            organization = config.OrganizationId is null ? null : new { id = config.OrganizationId },
            validity_days = config.MaxValidityDays
        };

        using var response = await http.PostAsJsonAsync($"order/certificate/{profileId}", payload, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"DigiCert order failed: {Trunc(body)}");

        var order = JsonDocument.Parse(body).RootElement;
        return new CaRequestRef(ConnectorType, order.GetProperty("id").ToString());
    }

    public async Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct)
    {
        using var http = Client();
        using var response = await http.GetAsync($"order/certificate/{request.ProviderRequestId}", ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode) return new CaRequestStatus(CaRequestState.Failed, Trunc(body));

        var order = JsonDocument.Parse(body).RootElement;
        var status = order.GetProperty("status").GetString();
        return status switch
        {
            "issued" => new CaRequestStatus(CaRequestState.Issued),
            "pending" or "needs_approval" => new CaRequestStatus(CaRequestState.ValidationRequired,
                "CertCentral is validating the order"),
            "rejected" or "canceled" => new CaRequestStatus(CaRequestState.Rejected, status),
            _ => new CaRequestStatus(CaRequestState.Pending, status)
        };
    }

    public async Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct)
    {
        using var http = Client();
        var order = JsonDocument.Parse(
            await http.GetStringAsync($"order/certificate/{request.ProviderRequestId}", ct)).RootElement;
        var certificateId = order.GetProperty("certificate").GetProperty("id").ToString();

        var bundle = await http.GetStringAsync(
            $"certificate/{certificateId}/download/format/pem_all", ct);
        return AcmeConnector.SplitBundle(bundle);
    }

    public Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId,
        CancellationToken ct) =>
        SubmitRequestAsync(csrPem, profileId, new Dictionary<string, string>(), ct);

    public async Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct)
    {
        using var http = Client();
        using var response = await http.PutAsJsonAsync(
            $"certificate/{certificateSerial}/revoke", new { comments = reason.ToString() }, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"DigiCert revocation failed: {(int)response.StatusCode}");
    }

    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method,
        CancellationToken ct) =>
        // CertCentral validates domains at the organization level, outside a single order.
        Task.FromResult<DomainValidationChallenge?>(null);

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}

/// <summary>
/// A generic REST CA (design doc §18.3): Sectigo SCM, an internal issuing service, or anything
/// else that speaks "post a CSR, poll an id, download a PEM". The endpoint paths are configuration
/// rather than code, because that is the only part that differs between them.
/// </summary>
public class GenericRestCaConnector(RestCaConfig config, GenericRestCaConfig paths,
    IHttpClientFactory? httpFactory = null) : ICertificateAuthorityConnector
{
    public string ConnectorType => paths.ConnectorType;

    private HttpClient Client()
    {
        var http = httpFactory?.CreateClient("rest-ca") ?? new HttpClient();
        http.BaseAddress = new Uri(config.BaseUrl.TrimEnd('/') + "/");
        http.Timeout = TimeSpan.FromSeconds(60);
        if (config.ApiKeyHeader.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", config.ApiKey);
        else
            http.DefaultRequestHeaders.TryAddWithoutValidation(config.ApiKeyHeader, config.ApiKey);
        return http;
    }

    public async Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct)
    {
        try
        {
            using var http = Client();
            using var response = await http.GetAsync(paths.HealthPath, ct);
            return response.IsSuccessStatusCode
                ? new CaConnectionResult(true)
                : new CaConnectionResult(false, $"the CA returned {(int)response.StatusCode}");
        }
        catch (Exception ex) { return new CaConnectionResult(false, ex.Message); }
    }

    public Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<CaProfile>>(config.Profiles
            .Select(p => new CaProfile(p, $"{paths.DisplayName} — {p}", ["RSA", "EC"],
                config.MaxValidityDays, true, "{}"))
            .ToList());

    public async Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId,
        IReadOnlyDictionary<string, string> metadata, CancellationToken ct)
    {
        using var http = Client();
        using var response = await http.PostAsJsonAsync(paths.SubmitPath, new
        {
            csr = csrPem,
            profile = profileId,
            organizationId = config.OrganizationId,
            commonName = metadata.GetValueOrDefault("commonName"),
            validityDays = config.MaxValidityDays
        }, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"{paths.DisplayName} submission failed: {Trunc(body)}");

        var json = JsonDocument.Parse(body).RootElement;
        return new CaRequestRef(ConnectorType,
            json.TryGetProperty(paths.RequestIdField, out var id)
                ? id.ToString()
                : throw new InvalidOperationException(
                    $"The response has no '{paths.RequestIdField}' field to use as a request id."));
    }

    public async Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct)
    {
        using var http = Client();
        using var response = await http.GetAsync(
            paths.StatusPath.Replace("{id}", Uri.EscapeDataString(request.ProviderRequestId)), ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode) return new CaRequestStatus(CaRequestState.Failed, Trunc(body));

        var json = JsonDocument.Parse(body).RootElement;
        var status = json.TryGetProperty(paths.StatusField, out var s) ? s.ToString().ToLowerInvariant() : "";
        if (paths.IssuedValues.Any(v => status.Contains(v, StringComparison.OrdinalIgnoreCase)))
            return new CaRequestStatus(CaRequestState.Issued);
        if (paths.RejectedValues.Any(v => status.Contains(v, StringComparison.OrdinalIgnoreCase)))
            return new CaRequestStatus(CaRequestState.Rejected, status);
        return new CaRequestStatus(CaRequestState.Pending, status);
    }

    public async Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct)
    {
        using var http = Client();
        var body = await http.GetStringAsync(
            paths.DownloadPath.Replace("{id}", Uri.EscapeDataString(request.ProviderRequestId)), ct);

        // The response is either a PEM bundle or JSON carrying one; both are common.
        if (body.TrimStart().StartsWith('{'))
        {
            var json = JsonDocument.Parse(body).RootElement;
            body = json.TryGetProperty(paths.CertificateField, out var pem)
                ? pem.GetString() ?? ""
                : throw new InvalidOperationException(
                    $"The response has no '{paths.CertificateField}' field carrying the certificate.");
        }
        return AcmeConnector.SplitBundle(body);
    }

    public Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId,
        CancellationToken ct) =>
        SubmitRequestAsync(csrPem, profileId, new Dictionary<string, string>(), ct);

    public async Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(paths.RevokePath))
            throw new NotSupportedException($"{paths.DisplayName} has no revocation endpoint configured.");

        using var http = Client();
        using var response = await http.PostAsJsonAsync(
            paths.RevokePath.Replace("{id}", Uri.EscapeDataString(certificateSerial)),
            new { reason = reason.ToString() }, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"{paths.DisplayName} revocation failed: {(int)response.StatusCode}");
    }

    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method,
        CancellationToken ct) => Task.FromResult<DomainValidationChallenge?>(null);

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}

/// <summary>
/// The endpoint shape of a generic REST CA. Sectigo SCM ships as a preset; anything else is
/// described here instead of needing new code.
/// </summary>
public sealed class GenericRestCaConfig
{
    public string ConnectorType { get; set; } = "rest-ca";
    public string DisplayName { get; set; } = "REST CA";
    public string HealthPath { get; set; } = "health";
    public string SubmitPath { get; set; } = "certificates";
    public string StatusPath { get; set; } = "certificates/{id}";
    public string DownloadPath { get; set; } = "certificates/{id}/download";
    public string? RevokePath { get; set; } = "certificates/{id}/revoke";
    public string RequestIdField { get; set; } = "id";
    public string StatusField { get; set; } = "status";
    public string CertificateField { get; set; } = "certificate";
    public List<string> IssuedValues { get; set; } = ["issued", "valid", "complete"];
    public List<string> RejectedValues { get; set; } = ["rejected", "denied", "failed", "revoked"];

    /// <summary>Sectigo Certificate Manager's SSL endpoints (§18.3).</summary>
    public static GenericRestCaConfig Sectigo() => new()
    {
        ConnectorType = "sectigo",
        DisplayName = "Sectigo Certificate Manager",
        HealthPath = "api/ssl/v1/types",
        SubmitPath = "api/ssl/v1/enroll",
        StatusPath = "api/ssl/v1/{id}",
        DownloadPath = "api/ssl/v1/collect/{id}/x509CO",
        RevokePath = "api/ssl/v1/revoke/{id}",
        RequestIdField = "sslId",
        StatusField = "status",
        CertificateField = "certificate",
        IssuedValues = ["issued", "applied"],
        RejectedValues = ["rejected", "revoked", "expired"]
    };
}
