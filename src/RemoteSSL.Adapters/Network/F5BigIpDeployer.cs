using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using RemoteSSL.Adapters.Linux;

namespace RemoteSSL.Adapters.Network;

public sealed class F5DeployPayload
{
    public string ManagementUrl { get; set; } = string.Empty; // https://bigip.mgmt
    public Guid? CredentialRefId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Partition { get; set; } = "Common";
    public string CertObjectName { get; set; } = string.Empty;   // e.g. company-com
    public string ClientSslProfile { get; set; } = string.Empty; // e.g. company-clientssl
    public string CertPem { get; set; } = string.Empty;
    public string KeyPem { get; set; } = string.Empty;
    public string? ChainPem { get; set; }
    public bool AllowInsecureTls { get; set; }
    /// <summary>Standby-first HA safety: refuse to touch an active unit unless explicitly allowed.</summary>
    public bool AllowActiveUnit { get; set; } = true;
}

/// <summary>
/// F5 BIG-IP certificate deployment via iControl REST (design doc §14): upload
/// cert/key as new timestamped objects, then re-point the client-ssl profile.
/// Rollback re-points the profile at the previously bound objects — the old
/// cert/key objects are never deleted during deployment.
/// </summary>
public static class F5BigIpDeployer
{
    public static async Task<DeployOutcome> DeployAsync(F5DeployPayload p, CancellationToken ct = default)
    {
        var steps = new List<StepOutcome>();
        var handler = new HttpClientHandler();
        if (p.AllowInsecureTls)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        using var http = new HttpClient(handler) { BaseAddress = new Uri(p.ManagementUrl), Timeout = TimeSpan.FromSeconds(60) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{p.Username}:{p.Password}")));

        var ts = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
        var certName = $"{p.CertObjectName}-{ts}.crt";
        var keyName = $"{p.CertObjectName}-{ts}.key";
        var profilePath = $"~{p.Partition}~{p.ClientSslProfile}";
        string? previousCert = null, previousKey = null;

        try
        {
            // PRE-CHECK: reachability + failover state + record current profile binding
            var fo = await http.GetAsync("/mgmt/tm/sys/failover", ct);
            if (!fo.IsSuccessStatusCode)
            {
                steps.Add(new("PreCheck", false, $"management API unreachable: {(int)fo.StatusCode}"));
                return new DeployOutcome(false, false, steps);
            }
            var foBody = await fo.Content.ReadAsStringAsync(ct);
            var isActive = foBody.Contains("active", StringComparison.OrdinalIgnoreCase);
            if (isActive && !p.AllowActiveUnit)
            {
                steps.Add(new("PreCheck", false, "unit is ACTIVE and standby-first policy is set"));
                return new DeployOutcome(false, false, steps);
            }

            var prof = await http.GetAsync($"/mgmt/tm/ltm/profile/client-ssl/{profilePath}", ct);
            if (prof.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(await prof.Content.ReadAsStringAsync(ct));
                previousCert = doc.RootElement.TryGetProperty("cert", out var c) ? c.GetString() : null;
                previousKey = doc.RootElement.TryGetProperty("key", out var k) ? k.GetString() : null;
            }
            steps.Add(new("PreCheck", true, $"failover={(isActive ? "active" : "standby")}, profile cert={previousCert ?? "n/a"}"));

            // INSTALL: upload + create cert/key objects (old objects untouched = backup)
            var certContent = p.ChainPem is null ? p.CertPem : p.CertPem.Trim() + "\n" + p.ChainPem.Trim();
            if (!await UploadAndCreate(http, "cert", certName, certContent, p.Partition, steps, ct)) return new DeployOutcome(false, false, steps);
            if (!await UploadAndCreate(http, "key", keyName, p.KeyPem, p.Partition, steps, ct)) return new DeployOutcome(false, false, steps);
            steps.Add(new("Install", true, $"objects /{p.Partition}/{certName}, /{p.Partition}/{keyName} created"));

            // ACTIVATE: re-point client-ssl profile
            var patch = await http.PatchAsJsonAsync($"/mgmt/tm/ltm/profile/client-ssl/{profilePath}",
                new { cert = $"/{p.Partition}/{certName}", key = $"/{p.Partition}/{keyName}" }, ct);
            if (!patch.IsSuccessStatusCode)
            {
                steps.Add(new("Activate", false, $"profile patch failed: {(int)patch.StatusCode} {Trunc(await patch.Content.ReadAsStringAsync(ct))}"));
                return await Rollback(http, steps, profilePath, previousCert, previousKey, ct);
            }
            steps.Add(new("Activate", true, $"profile {p.ClientSslProfile} re-pointed"));

            // VERIFY readback
            var verify = await http.GetAsync($"/mgmt/tm/ltm/profile/client-ssl/{profilePath}", ct);
            var body = await verify.Content.ReadAsStringAsync(ct);
            if (!body.Contains(certName))
            {
                steps.Add(new("LocalVerify", false, "profile readback does not show new cert"));
                return await Rollback(http, steps, profilePath, previousCert, previousKey, ct);
            }
            steps.Add(new("LocalVerify", true, "profile binding verified"));
            steps.Add(new("Commit", true, $"previous objects retained: {previousCert}/{previousKey}"));
            return new DeployOutcome(true, false, steps);
        }
        catch (Exception ex)
        {
            steps.Add(new("Error", false, Trunc(ex.Message)));
            return await Rollback(http, steps, profilePath, previousCert, previousKey, ct);
        }
    }

    private static async Task<bool> UploadAndCreate(HttpClient http, string kind, string name,
        string pemContent, string partition, List<StepOutcome> steps, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(pemContent);
        var upload = new HttpRequestMessage(HttpMethod.Post, $"/mgmt/shared/file-transfer/uploads/{name}")
        {
            Content = new ByteArrayContent(bytes)
        };
        upload.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        upload.Content.Headers.ContentRange = new ContentRangeHeaderValue(0, bytes.Length - 1, bytes.Length);
        var up = await http.SendAsync(upload, ct);
        if (!up.IsSuccessStatusCode)
        {
            steps.Add(new("Install", false, $"{kind} upload failed: {(int)up.StatusCode}"));
            return false;
        }

        var create = await http.PostAsJsonAsync($"/mgmt/tm/sys/crypto/{kind}",
            new { name, partition, fromLocalFile = $"/var/config/rest/downloads/{name}" }, ct);
        if (!create.IsSuccessStatusCode)
        {
            steps.Add(new("Install", false, $"{kind} object create failed: {(int)create.StatusCode} {Trunc(await create.Content.ReadAsStringAsync(ct))}"));
            return false;
        }
        return true;
    }

    private static async Task<DeployOutcome> Rollback(HttpClient http, List<StepOutcome> steps,
        string profilePath, string? previousCert, string? previousKey, CancellationToken ct)
    {
        if (previousCert is null || previousKey is null)
        {
            steps.Add(new("Rollback", false, "no previous binding recorded"));
            return new DeployOutcome(false, false, steps);
        }
        var patch = await http.PatchAsJsonAsync($"/mgmt/tm/ltm/profile/client-ssl/{profilePath}",
            new { cert = previousCert, key = previousKey }, ct);
        var ok = patch.IsSuccessStatusCode;
        steps.Add(new("Rollback", ok, ok ? $"profile restored to {previousCert}" : $"restore failed: {(int)patch.StatusCode}"));
        return new DeployOutcome(false, ok, steps);
    }

    private static string Trunc(string s) => s.Length <= 300 ? s : s[..300];
}
