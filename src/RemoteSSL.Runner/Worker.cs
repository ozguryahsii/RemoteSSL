using System.Net.Http.Json;
using System.Text.Json;
using RemoteSSL.Adapters.Java;
using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Network;
using RemoteSSL.Adapters.Oracle;
using RemoteSSL.Adapters.Ssh;
using RemoteSSL.Adapters.Windows;

namespace RemoteSSL.Runner;

/// <summary>
/// Runner main loop (design doc §8): register with a bootstrap token, heartbeat with
/// capabilities, claim jobs, resolve credentials at execution time, run the adapter
/// pipeline and report step results. All connections are outbound to the control
/// plane; the control plane never dials the runner.
/// </summary>
public class Worker(IConfiguration config, IHttpClientFactory httpFactory, ILogger<Worker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private Guid _runnerId;
    private string _apiKey = string.Empty;
    private static readonly string[] Capabilities = ["ssh", "sftp", "linux-deploy", "windows-deploy", "java-keystore", "oracle-wallet", "f5-bigip"];

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var baseUrl = config["ControlPlane:Url"] ?? "http://localhost:5200";
        var http = httpFactory.CreateClient("control-plane");
        http.BaseAddress = new Uri(baseUrl);

        while (!ct.IsCancellationRequested && !await RegisterAsync(http, ct))
            await Task.Delay(TimeSpan.FromSeconds(10), ct);

        var pollInterval = TimeSpan.FromSeconds(config.GetValue("Runner:PollSeconds", 5));
        var lastHeartbeat = DateTimeOffset.MinValue;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (DateTimeOffset.UtcNow - lastHeartbeat > TimeSpan.FromSeconds(30))
                {
                    await PostAsync(http, $"api/v1/runners/{_runnerId}/heartbeat",
                        new { capabilities = Capabilities, version = "1.0.0" }, ct);
                    lastHeartbeat = DateTimeOffset.UtcNow;
                }

                var claim = await PostAsync(http, $"api/v1/runners/{_runnerId}/jobs/claim", null, ct);
                if (claim.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    var job = await claim.Content.ReadFromJsonAsync<ClaimedJob>(Json, ct);
                    if (job is not null) await ExecuteJobAsync(http, job, ct);
                    continue; // immediately look for the next job
                }
                if (claim.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    logger.LogWarning("API key rejected — re-registering");
                    await RegisterAsync(http, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogError(ex, "Runner loop error");
            }
            await Task.Delay(pollInterval, ct);
        }
    }

    private sealed record ClaimedJob(Guid Id, string JobType, string PayloadJson, string CorrelationId, string? Signature);

    private async Task<bool> RegisterAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            var res = await http.PostAsJsonAsync("api/v1/runners/register", new
            {
                bootstrapToken = config["Runner:BootstrapToken"] ?? "",
                name = config["Runner:Name"] ?? Environment.MachineName,
                segment = config["Runner:Segment"],
                capabilities = Capabilities,
                version = "1.0.0"
            }, Json, ct);
            if (!res.IsSuccessStatusCode)
            {
                logger.LogError("Registration failed: {Status}", res.StatusCode);
                return false;
            }
            var body = await res.Content.ReadFromJsonAsync<JsonElement>(Json, ct);
            _runnerId = body.GetProperty("runnerId").GetGuid();
            _apiKey = body.GetProperty("apiKey").GetString()!;
            logger.LogInformation("Registered as runner {Id}", _runnerId);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError("Registration error: {Error}", ex.Message);
            return false;
        }
    }

    private async Task ExecuteJobAsync(HttpClient http, ClaimedJob job, CancellationToken ct)
    {
        logger.LogInformation("Executing job {Id} ({Type})", job.Id, job.JobType);
        bool success = false, rolledBack = false;
        var steps = new List<object>();
        string? resultJson = null;

        // Refuse jobs without a valid short-lived signature (design doc §8.2)
        var signingSecret = config["Runner:JobSigningSecret"] ?? config["Runner:BootstrapToken"] ?? "";
        if (job.Signature is null || !RemoteSSL.Domain.Abstractions.JobSigner.Verify(
                signingSecret, job.Id, job.PayloadJson, job.Signature, DateTimeOffset.UtcNow))
        {
            logger.LogWarning("Job {Id} rejected: missing or invalid signature", job.Id);
            await PostAsync(http, $"api/v1/runners/{_runnerId}/jobs/{job.Id}/complete",
                new { success = false, rolledBack = false, steps = new[] { new { step = "PreCheck", success = false, safeLog = "job signature invalid or expired" } }, resultJson = (string?)null }, ct);
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(job.PayloadJson);
            var kind = doc.RootElement.GetProperty("kind").GetString();
            var creds = await ResolveCredentialsAsync(http, doc.RootElement, ct);

            if (job.JobType == "generate-csr")
            {
                var (ok, csrPem, log) = GenerateCsrOnTarget(doc.RootElement, creds);
                success = ok;
                resultJson = JsonSerializer.Serialize(new { csrPem });
                steps.Add(new { step = "PreCheck", success = ok, safeLog = log });
            }
            else if (job.JobType == "discover")
            {
                var (ok, output) = DiscoverStores(doc.RootElement, kind, creds);
                success = ok;
                resultJson = JsonSerializer.Serialize(new { output });
                steps.Add(new { step = "PreCheck", success = ok, safeLog = ok ? "store discovery completed" : output });
            }
            else if (job.JobType == "test-connection")
            {
                var conn = doc.RootElement.GetProperty("connection").Deserialize<SshTargetConfig>(Json)!;
                using var ssh = new SshConnection(conn, creds);
                ssh.Connect();
                var r = ssh.Exec("uname -a || ver");
                success = r.Ok;
                resultJson = JsonSerializer.Serialize(new { r.ExitCode, Output = r.Stdout.Trim() });
                steps.Add(new { step = "PreCheck", success, safeLog = success ? "connected" : r.Stderr });
            }
            else if (job.JobType == "deploy")
            {
                DeployOutcome outcome = kind switch
                {
                    "linux" => LinuxDeployer.Deploy(doc.RootElement.Deserialize<DeployPayload>(Json)!, creds),
                    "windows" => WindowsDeployer.Deploy(ToWindowsPayload(doc.RootElement), creds),
                    "java" => JavaKeystoreDeployer.Deploy(ToJavaPayload(doc.RootElement, creds), creds),
                    "oracle" => OracleWalletDeployer.Deploy(ToOraclePayload(doc.RootElement, creds), creds),
                    "f5" => await F5BigIpDeployer.DeployAsync(ToF5Payload(doc.RootElement, creds), ct),
                    "vendor" => await VendorDeployers.DeployAsync(ToVendorPayload(doc.RootElement, creds), ct),
                    _ => new DeployOutcome(false, false, [new("PreCheck", false, $"unknown payload kind '{kind}'")])
                };
                success = outcome.Success;
                rolledBack = outcome.RolledBack;
                steps.AddRange(outcome.Steps.Select(s => new { step = s.Step, success = s.Success, safeLog = s.SafeLog }));
            }
            else
            {
                steps.Add(new { step = "PreCheck", success = false, safeLog = $"unknown job type '{job.JobType}'" });
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job {Id} crashed", job.Id);
            steps.Add(new { step = "Error", success = false, safeLog = ex.Message });
        }

        await PostAsync(http, $"api/v1/runners/{_runnerId}/jobs/{job.Id}/complete",
            new { success, rolledBack, steps, resultJson }, ct);
        logger.LogInformation("Job {Id} finished: {Result}", job.Id, success ? "SUCCESS" : rolledBack ? "ROLLED_BACK" : "FAILED");
    }

    private async Task<SshCredentials> ResolveCredentialsAsync(HttpClient http, JsonElement payload, CancellationToken ct)
    {
        if (!payload.TryGetProperty("credentialRefId", out var credId) || credId.ValueKind == JsonValueKind.Null)
            return new SshCredentials("root", null, null);

        var res = await GetAsync(http, $"api/v1/runners/{_runnerId}/credentials/{credId.GetGuid()}", ct);
        res.EnsureSuccessStatusCode();
        var body = await res.Content.ReadFromJsonAsync<JsonElement>(Json, ct);
        var secretJson = JsonDocument.Parse(body.GetProperty("secret").GetString()!).RootElement;
        return new SshCredentials(
            body.TryGetProperty("username", out var u) ? u.GetString() ?? "root" : "root",
            secretJson.TryGetProperty("Password", out var pw) ? pw.GetString() : null,
            secretJson.TryGetProperty("PrivateKeyPem", out var pk) ? pk.GetString() : null);
    }

    private static WindowsDeployPayload ToWindowsPayload(JsonElement e) => new()
    {
        Connection = e.GetProperty("connection").Deserialize<SshTargetConfig>(Json)!,
        Method = e.TryGetProperty("method", out var m) ? m.GetString() ?? "winrm" : "winrm",
        WinRmUseSsl = e.TryGetProperty("winRmUseSsl", out var ws) && ws.GetBoolean(),
        StorePath = e.GetProperty("storePath").GetString()!,
        PfxBytes = Convert.FromBase64String(e.GetProperty("pfxBase64").GetString()!),
        PfxPassword = e.GetProperty("pfxPassword").GetString()!,
        IisSiteName = e.TryGetProperty("iisSiteName", out var s) ? s.GetString() : null,
        IisHostHeader = e.TryGetProperty("iisHostHeader", out var h) ? h.GetString() : null,
        IisPort = e.TryGetProperty("iisPort", out var p) ? p.GetInt32() : 443,
        ExpectedSha1Thumbprint = e.TryGetProperty("expectedSha1Thumbprint", out var t) ? t.GetString() : null
    };

    private static JavaKeystorePayload ToJavaPayload(JsonElement e, SshCredentials creds) => new()
    {
        Connection = e.GetProperty("connection").Deserialize<SshTargetConfig>(Json)!,
        StorePath = e.GetProperty("storePath").GetString()!,
        StoreType = e.TryGetProperty("storeType", out var st) ? st.GetString() ?? "JKS" : "JKS",
        Alias = e.GetProperty("alias").GetString()!,
        KeytoolPath = e.TryGetProperty("keytoolPath", out var kt) ? kt.GetString() : null,
        StorePassword = creds.Password ?? "changeit",
        CertPem = e.GetProperty("certPem").GetString()!,
        Pkcs12Bundle = e.TryGetProperty("pkcs12Base64", out var p12) && p12.ValueKind == JsonValueKind.String
            ? Convert.FromBase64String(p12.GetString()!) : null,
        Pkcs12Password = e.TryGetProperty("pkcs12Password", out var pp) ? pp.GetString() : null,
        ReloadCmd = e.TryGetProperty("reloadCmd", out var rc) ? rc.GetString() : null
    };

    private static OracleWalletPayload ToOraclePayload(JsonElement e, SshCredentials creds) => new()
    {
        Connection = e.GetProperty("connection").Deserialize<SshTargetConfig>(Json)!,
        WalletPath = e.GetProperty("walletPath").GetString()!,
        OrapkiPath = e.TryGetProperty("orapkiPath", out var op) ? op.GetString() : null,
        WalletPassword = creds.Password ?? "",
        CertKind = e.TryGetProperty("certKind", out var ck) ? ck.GetString() ?? "trusted" : "trusted",
        CertPem = e.GetProperty("certPem").GetString()!,
        ReloadCmd = e.TryGetProperty("reloadCmd", out var rc) ? rc.GetString() : null
    };

    /// <summary>Remote store discovery (design doc §27.1): certificate files / store entries on the target.</summary>
    private (bool Ok, string Output) DiscoverStores(JsonElement e, string? kind, SshCredentials creds)
    {
        var conn = e.GetProperty("connection").Deserialize<SshTargetConfig>(Json)!;
        try
        {
            if (kind == "windows")
            {
                var method = e.TryGetProperty("method", out var m) ? m.GetString() ?? "winrm" : "winrm";
                var useSsl = e.TryGetProperty("winRmUseSsl", out var ws) && ws.GetBoolean();
                using IWindowsChannel channel = method == "ssh"
                    ? new SshWindowsChannel(conn, creds)
                    : new WinRmWindowsChannel(conn.Host, conn.Port, useSsl, creds.Username, creds.Password ?? "");
                var r = channel.RunPs(
                    "Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Subject,Thumbprint,NotAfter | Format-Table -AutoSize | Out-String -Width 200");
                return (r.Ok, r.Ok ? r.Stdout.Trim() : r.Stderr);
            }

            using var ssh = new SshConnection(conn, creds);
            ssh.Connect();
            var find = ssh.Exec(
                "find /etc/ssl /etc/nginx /etc/apache2 /etc/httpd /etc/haproxy /etc/pki -maxdepth 4 " +
                "\\( -name '*.crt' -o -name '*.pem' -o -name '*.jks' -o -name '*.p12' -o -name 'ewallet.p12' \\) " +
                "2>/dev/null | head -100", TimeSpan.FromMinutes(1));
            return (true, find.Stdout.Trim().Length > 0 ? find.Stdout.Trim() : "no certificate files found in common locations");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>On-target key + CSR via openssl over SSH; the key never leaves the target (design doc §16.1).</summary>
    private (bool Ok, string? CsrPem, string Log) GenerateCsrOnTarget(JsonElement e, SshCredentials creds)
    {
        var conn = e.GetProperty("connection").Deserialize<SshTargetConfig>(Json)!;
        var keyPath = e.GetProperty("keyPath").GetString()!;
        var cn = e.GetProperty("commonName").GetString()!;
        var sans = e.TryGetProperty("sans", out var s)
            ? s.EnumerateArray().Select(x => x.GetString()).Where(x => x is not null).ToList()
            : [];
        var alg = e.TryGetProperty("keyAlgorithm", out var a) ? a.GetString() ?? "RSA" : "RSA";
        var size = e.TryGetProperty("keySizeOrCurve", out var k) ? k.GetInt32() : 2048;

        using var ssh = new SshConnection(conn, creds);
        try { ssh.Connect(); }
        catch (Exception ex) { return (false, null, $"ssh connect failed: {ex.Message}"); }

        if (!ssh.Exec("command -v openssl").Ok) return (false, null, "openssl not found on target");

        var genKey = alg.Equals("EC", StringComparison.OrdinalIgnoreCase)
            ? $"openssl ecparam -name {(size >= 384 ? "secp384r1" : "prime256v1")} -genkey -noout -out {Shell.Quote(keyPath)}"
            : $"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:{Math.Max(size, 2048)} -out {Shell.Quote(keyPath)}";
        var r = ssh.Exec($"umask 077 && {genKey} && chmod 0600 {Shell.Quote(keyPath)}");
        if (!r.Ok) return (false, null, $"key generation failed: {r.Stderr}");

        var sanList = string.Join(",", sans.Select(x => $"DNS:{x}"));
        var csrCmd = $"openssl req -new -key {Shell.Quote(keyPath)} -subj {Shell.Quote($"/CN={cn}")}"
                     + (sanList.Length > 0 ? $" -addext {Shell.Quote($"subjectAltName={sanList}")}" : "");
        var csr = ssh.Exec(csrCmd);
        if (!csr.Ok || !csr.Stdout.Contains("BEGIN CERTIFICATE REQUEST"))
            return (false, null, $"csr generation failed: {csr.Stderr}");
        return (true, csr.Stdout, $"key {keyPath} (0600) + CSR generated on target");
    }

    private static VendorDeployPayload ToVendorPayload(JsonElement e, SshCredentials creds) => new()
    {
        Vendor = e.GetProperty("vendor").GetString()!,
        ManagementUrl = e.GetProperty("managementUrl").GetString()!,
        Username = creds.Username,
        Password = creds.Password ?? "",
        ApiToken = e.TryGetProperty("apiToken", out var at) ? at.GetString() : null,
        CertObjectName = e.GetProperty("certObjectName").GetString()!,
        BindingRef = e.TryGetProperty("bindingRef", out var br) ? br.GetString() : null,
        CertPem = e.GetProperty("certPem").GetString()!,
        KeyPem = e.TryGetProperty("keyPem", out var kp) && kp.ValueKind == JsonValueKind.String ? kp.GetString() : null,
        ChainPem = e.TryGetProperty("chainPem", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null,
        AllowInsecureTls = e.TryGetProperty("allowInsecureTls", out var ai) && ai.GetBoolean()
    };

    private static F5DeployPayload ToF5Payload(JsonElement e, SshCredentials creds) => new()
    {
        ManagementUrl = e.GetProperty("managementUrl").GetString()!,
        Username = creds.Username,
        Password = creds.Password ?? "",
        Partition = e.TryGetProperty("partition", out var p) ? p.GetString() ?? "Common" : "Common",
        CertObjectName = e.GetProperty("certObjectName").GetString()!,
        ClientSslProfile = e.GetProperty("clientSslProfile").GetString()!,
        CertPem = e.GetProperty("certPem").GetString()!,
        KeyPem = e.GetProperty("keyPem").GetString()!,
        ChainPem = e.TryGetProperty("chainPem", out var c) ? c.GetString() : null,
        AllowInsecureTls = e.TryGetProperty("allowInsecureTls", out var a) && a.GetBoolean()
    };

    private Task<HttpResponseMessage> PostAsync(HttpClient http, string path, object? body, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = body is null ? null : JsonContent.Create(body, options: Json)
        };
        req.Headers.Add("X-Runner-Key", _apiKey);
        return http.SendAsync(req, ct);
    }

    private Task<HttpResponseMessage> GetAsync(HttpClient http, string path, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Add("X-Runner-Key", _apiKey);
        return http.SendAsync(req, ct);
    }
}
