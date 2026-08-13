using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using RemoteSSL.Adapters.Linux;

namespace RemoteSSL.Adapters.Network;

/// <summary>Common payload for REST-managed network devices (FortiGate, Palo Alto, Citrix ADC, Cisco ISE).</summary>
public sealed class VendorDeployPayload
{
    public string Vendor { get; set; } = string.Empty; // fortigate | paloalto | citrix-adc | cisco-ise
    public string ManagementUrl { get; set; } = string.Empty;
    public Guid? CredentialRefId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    /// <summary>API key/token for vendors using token auth (FortiGate/PA). Falls back to Password.</summary>
    public string? ApiToken { get; set; }
    public string CertObjectName { get; set; } = string.Empty;
    /// <summary>Vendor-specific binding: PA template/vsys, ADC vserver name, ISE usage list…</summary>
    public string? BindingRef { get; set; }
    public string CertPem { get; set; } = string.Empty;
    public string? KeyPem { get; set; }
    public string? ChainPem { get; set; }
    public bool AllowInsecureTls { get; set; }
}

/// <summary>
/// Vendor network-device deployers (design doc §14). Each implementation imports the
/// certificate as a NEW named object, then re-points the binding — the previous
/// object is never deleted, so rollback is re-pointing to the old name. These use
/// documented vendor REST APIs (FortiOS monitor API, PAN-OS XML API, Citrix Nitro,
/// Cisco ISE ERS) and must be validated against real devices/lab before production.
/// </summary>
public static class VendorDeployers
{
    public static async Task<DeployOutcome> DeployAsync(VendorDeployPayload p, CancellationToken ct) => p.Vendor switch
    {
        "fortigate" => await FortiGateAsync(p, ct),
        "paloalto" => await PaloAltoAsync(p, ct),
        "citrix-adc" => await CitrixAdcAsync(p, ct),
        "cisco-ise" => await CiscoIseAsync(p, ct),
        _ => new DeployOutcome(false, false, [new("PreCheck", false, $"unknown vendor '{p.Vendor}'")])
    };

    private static HttpClient Client(VendorDeployPayload p)
    {
        var handler = new HttpClientHandler();
        if (p.AllowInsecureTls)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return new HttpClient(handler) { BaseAddress = new Uri(p.ManagementUrl), Timeout = TimeSpan.FromSeconds(60) };
    }

    private static string Ts() => DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
    private static string FullCert(VendorDeployPayload p) =>
        p.ChainPem is null ? p.CertPem : p.CertPem.Trim() + "\n" + p.ChainPem.Trim();

    // ---- FortiGate (FortiOS REST, token auth) -------------------------------------------------
    private static async Task<DeployOutcome> FortiGateAsync(VendorDeployPayload p, CancellationToken ct)
    {
        var steps = new List<StepOutcome>();
        using var http = Client(p);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", p.ApiToken ?? p.Password);
        var name = $"{p.CertObjectName}-{Ts()}";

        var ping = await http.GetAsync("/api/v2/monitor/system/status", ct);
        if (!ping.IsSuccessStatusCode)
        {
            steps.Add(new("PreCheck", false, $"management API unreachable: {(int)ping.StatusCode}"));
            return new DeployOutcome(false, false, steps);
        }
        steps.Add(new("PreCheck", true, "API reachable"));

        var import = await http.PostAsJsonAsync("/api/v2/monitor/vpn-certificate/local/import", new
        {
            type = "regular",
            certname = name,
            file_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(FullCert(p))),
            key_file_content = p.KeyPem is null ? null : Convert.ToBase64String(Encoding.UTF8.GetBytes(p.KeyPem)),
            scope = "global"
        }, ct);
        if (!import.IsSuccessStatusCode)
        {
            steps.Add(new("Install", false, $"import failed: {(int)import.StatusCode}"));
            return new DeployOutcome(false, false, steps);
        }
        steps.Add(new("Install", true, $"certificate object '{name}' imported"));

        if (p.BindingRef is not null) // admin GUI cert binding: system.global admin-server-cert
        {
            var bind = await http.SendAsync(new HttpRequestMessage(HttpMethod.Put, "/api/v2/cmdb/system/global")
            { Content = JsonContent.Create(new { json = new Dictionary<string, string> { [p.BindingRef] = name } }) }, ct);
            if (!bind.IsSuccessStatusCode)
            {
                steps.Add(new("Activate", false, $"binding update failed: {(int)bind.StatusCode}"));
                return new DeployOutcome(false, false, steps);
            }
            steps.Add(new("Activate", true, $"{p.BindingRef} → {name}"));
        }
        steps.Add(new("Commit", true, "previous certificate object retained for rollback"));
        return new DeployOutcome(true, false, steps);
    }

    // ---- Palo Alto (PAN-OS XML API, key auth) -------------------------------------------------
    private static async Task<DeployOutcome> PaloAltoAsync(VendorDeployPayload p, CancellationToken ct)
    {
        var steps = new List<StepOutcome>();
        using var http = Client(p);
        var key = p.ApiToken ?? p.Password;
        var name = $"{p.CertObjectName}-{Ts()}";

        async Task<(bool Ok, string Body)> Import(string category, string content, string? extra = null)
        {
            using var form = new MultipartFormDataContent { { new StringContent(content), "file", $"{name}.pem" } };
            var url = $"/api/?type=import&category={category}&certificate-name={name}&format=pem&key={Uri.EscapeDataString(key)}{extra}";
            var res = await http.PostAsync(url, form, ct);
            var body = await res.Content.ReadAsStringAsync(ct);
            return (res.IsSuccessStatusCode && body.Contains("success"), body);
        }

        var cert = await Import("certificate", FullCert(p));
        if (!cert.Ok)
        {
            steps.Add(new("Install", false, $"certificate import failed: {Trunc(cert.Body)}"));
            return new DeployOutcome(false, false, steps);
        }
        if (p.KeyPem is not null)
        {
            var pk = await Import("private-key", p.KeyPem, "&passphrase=");
            if (!pk.Ok)
            {
                steps.Add(new("Install", false, $"key import failed: {Trunc(pk.Body)}"));
                return new DeployOutcome(false, false, steps);
            }
        }
        steps.Add(new("Install", true, $"certificate '{name}' imported"));

        // COMMIT is mandatory on PAN-OS (design doc §14.3)
        var commit = await http.GetAsync($"/api/?type=commit&cmd=<commit></commit>&key={Uri.EscapeDataString(key)}", ct);
        var commitBody = await commit.Content.ReadAsStringAsync(ct);
        var committed = commit.IsSuccessStatusCode && commitBody.Contains("success");
        steps.Add(new("Commit", committed, committed ? "commit job submitted" : Trunc(commitBody)));
        return new DeployOutcome(committed, false, steps);
    }

    // ---- Citrix ADC (Nitro API) ----------------------------------------------------------------
    private static async Task<DeployOutcome> CitrixAdcAsync(VendorDeployPayload p, CancellationToken ct)
    {
        var steps = new List<StepOutcome>();
        using var http = Client(p);
        http.DefaultRequestHeaders.Add("X-NITRO-USER", p.Username);
        http.DefaultRequestHeaders.Add("X-NITRO-PASS", p.Password);
        var name = $"{p.CertObjectName}-{Ts()}";

        async Task<bool> UploadSystemFile(string filename, string content)
        {
            var res = await http.PostAsJsonAsync("/nitro/v1/config/systemfile", new
            {
                systemfile = new
                {
                    filename,
                    filelocation = "/nsconfig/ssl/",
                    filecontent = Convert.ToBase64String(Encoding.UTF8.GetBytes(content)),
                    fileencoding = "BASE64"
                }
            }, ct);
            return res.IsSuccessStatusCode;
        }

        if (!await UploadSystemFile($"{name}.crt", FullCert(p)) ||
            (p.KeyPem is not null && !await UploadSystemFile($"{name}.key", p.KeyPem)))
        {
            steps.Add(new("Install", false, "system file upload failed"));
            return new DeployOutcome(false, false, steps);
        }

        var certkey = await http.PostAsJsonAsync("/nitro/v1/config/sslcertkey", new
        {
            sslcertkey = new { certkey = name, cert = $"/nsconfig/ssl/{name}.crt", key = p.KeyPem is null ? null : $"/nsconfig/ssl/{name}.key" }
        }, ct);
        if (!certkey.IsSuccessStatusCode)
        {
            steps.Add(new("Install", false, $"sslcertkey create failed: {(int)certkey.StatusCode}"));
            return new DeployOutcome(false, false, steps);
        }
        steps.Add(new("Install", true, $"certkey '{name}' created"));

        if (p.BindingRef is not null)
        {
            var bind = await http.PutAsJsonAsync("/nitro/v1/config/sslvserver_sslcertkey_binding", new
            {
                sslvserver_sslcertkey_binding = new { vservername = p.BindingRef, certkeyname = name }
            }, ct);
            if (!bind.IsSuccessStatusCode)
            {
                steps.Add(new("Activate", false, $"vserver binding failed: {(int)bind.StatusCode}"));
                return new DeployOutcome(false, false, steps);
            }
            steps.Add(new("Activate", true, $"vserver '{p.BindingRef}' → {name}"));
        }
        var save = await http.PostAsJsonAsync("/nitro/v1/config/nsconfig?action=save", new { nsconfig = new { } }, ct);
        steps.Add(new("Commit", save.IsSuccessStatusCode, save.IsSuccessStatusCode ? "config saved" : "config save failed"));
        return new DeployOutcome(save.IsSuccessStatusCode, false, steps);
    }

    // ---- Cisco ISE (ERS API) -------------------------------------------------------------------
    private static async Task<DeployOutcome> CiscoIseAsync(VendorDeployPayload p, CancellationToken ct)
    {
        var steps = new List<StepOutcome>();
        using var http = Client(p);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{p.Username}:{p.Password}")));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var body = new
        {
            id = "",
            name = $"{p.CertObjectName}-{Ts()}",
            data = FullCert(p),
            privateKeyData = p.KeyPem,
            allowExtendedValidity = true,
            admin = p.BindingRef?.Contains("admin") ?? false,
            eap = p.BindingRef?.Contains("eap") ?? false,
            portal = p.BindingRef?.Contains("portal") ?? true
        };
        var res = await http.PostAsJsonAsync("/api/v1/certs/system-certificate/import", body, ct);
        var resBody = await res.Content.ReadAsStringAsync(ct);
        if (!res.IsSuccessStatusCode)
        {
            steps.Add(new("Install", false, $"ISE import failed: {(int)res.StatusCode} {Trunc(resBody)}"));
            return new DeployOutcome(false, false, steps);
        }
        steps.Add(new("Install", true, $"system certificate imported (usage: {p.BindingRef ?? "portal"})"));
        steps.Add(new("Commit", true, "ISE applies usage binding at import time"));
        return new DeployOutcome(true, false, steps);
    }

    private static string Trunc(string s) => s.Length <= 300 ? s : s[..300];
}
