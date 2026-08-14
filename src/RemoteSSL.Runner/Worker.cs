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
    /// <summary>Activity source name registered with OpenTelemetry in Program.cs (§32.2).</summary>
    public const string ActivitySourceName = "RemoteSSL.Runner";

    private static readonly System.Diagnostics.ActivitySource Activity = new(ActivitySourceName);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private Guid _runnerId;
    private string _apiKey = string.Empty;
    private static readonly string[] Capabilities = ["ssh", "sftp", "linux-deploy", "windows-deploy", "java-keystore", "oracle-wallet", "f5-bigip"];

    /// <summary>
    /// Adapter versions this runner ships, reported at registration and heartbeat so the
    /// control plane can pin versions before dispatching work (§30.2 supply chain).
    /// </summary>
    private static readonly Dictionary<string, string> AdapterVersions = new()
    {
        ["nginx"] = "1.0.0", ["apache"] = "1.0.0", ["haproxy"] = "1.0.0", ["generic-file"] = "1.0.0",
        ["iis"] = "1.0.0", ["windows-cert-store"] = "1.0.0",
        ["java-keystore"] = "1.0.0", ["java-truststore"] = "1.0.0", ["oracle-wallet"] = "1.0.0",
        ["f5-bigip"] = "1.0.0", ["fortigate"] = "1.0.0", ["paloalto"] = "1.0.0",
        ["citrix-adc"] = "1.0.0", ["cisco-ise"] = "1.0.0"
    };

    private System.Security.Cryptography.RSA? _identityKey;
    private System.Security.Cryptography.X509Certificates.X509Certificate2? _identityCertificate;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var baseUrl = config["ControlPlane:Url"] ?? "http://localhost:5200";
        var http = httpFactory.CreateClient("control-plane");
        http.BaseAddress = new Uri(baseUrl);

        while (!ct.IsCancellationRequested && !await RegisterAsync(http, ct))
            await Task.Delay(TimeSpan.FromSeconds(10), ct);

        // Once an identity certificate has been issued, every later call presents it, so the
        // control plane can require mutual TLS instead of trusting the API key alone (§8.2).
        if (_identityCertificate is not null)
        {
            http = CreateMutualTlsClient(baseUrl);
            logger.LogInformation("Using the runner identity certificate for control-plane calls");
        }

        var pollInterval = TimeSpan.FromSeconds(config.GetValue("Runner:PollSeconds", 5));
        var lastHeartbeat = DateTimeOffset.MinValue;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (DateTimeOffset.UtcNow - lastHeartbeat > TimeSpan.FromSeconds(30))
                {
                    await PostAsync(http, $"api/v1/runners/{_runnerId}/heartbeat",
                        new { capabilities = Capabilities, version = "1.0.0", adapterVersions = AdapterVersions }, ct);
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

    /// <summary>
    /// A client that presents the runner's identity certificate. Built by hand rather than via
    /// the factory because the certificate only exists after registration completes.
    /// </summary>
    private HttpClient CreateMutualTlsClient(string baseUrl)
    {
        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(_identityCertificate!);
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        return new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };
    }

    private async Task<bool> RegisterAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            // §8.2: the runner generates its own key pair and sends only the CSR, so the
            // private half of its identity never leaves this machine.
            var name = config["Runner:Name"] ?? Environment.MachineName;
            string? csrPem = null;
            if (config.GetValue("Runner:RequestIdentityCertificate", true))
            {
                _identityKey = System.Security.Cryptography.RSA.Create(2048);
                var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    $"CN={name}", _identityKey, System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                csrPem = request.CreateSigningRequestPem();
            }

            var res = await http.PostAsJsonAsync("api/v1/runners/register", new
            {
                bootstrapToken = config["Runner:BootstrapToken"] ?? "",
                name,
                segment = config["Runner:Segment"],
                capabilities = Capabilities,
                version = "1.0.0",
                csrPem,
                adapterVersions = AdapterVersions
            }, Json, ct);
            if (!res.IsSuccessStatusCode)
            {
                logger.LogError("Registration failed: {Status}", res.StatusCode);
                return false;
            }
            var body = await res.Content.ReadFromJsonAsync<JsonElement>(Json, ct);
            _runnerId = body.GetProperty("runnerId").GetGuid();
            _apiKey = body.GetProperty("apiKey").GetString()!;

            if (_identityKey is not null
                && body.TryGetProperty("certificatePem", out var certPem)
                && certPem.ValueKind == JsonValueKind.String)
            {
                // The key and certificate must be married before it can be presented as a
                // client credential; CreateFromPem gives the public half only.
                _identityCertificate = System.Security.Cryptography.X509Certificates.X509Certificate2
                    .CreateFromPem(certPem.GetString()!, _identityKey.ExportRSAPrivateKeyPem());
                logger.LogInformation("Received runner identity certificate (thumbprint {Thumbprint})",
                    _identityCertificate.Thumbprint);
            }

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
        // Job execution joins the control plane's trace via the correlation id it was issued with.
        using var activity = Activity.StartActivity($"runner.{job.JobType}", System.Diagnostics.ActivityKind.Consumer);
        activity?.SetTag("remotessl.correlation_id", job.CorrelationId);
        activity?.SetTag("remotessl.job_id", job.Id);

        logger.LogInformation("Executing job {Id} ({Type}) correlation {Correlation}",
            job.Id, job.JobType, job.CorrelationId);
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

            if (job.JobType == "probe")
            {
                var probeWatch = System.Diagnostics.Stopwatch.StartNew();
                resultJson = await ProbeEndpointAsync(doc.RootElement, ct);
                probeWatch.Stop();
                // The control plane records probe_latency (§32.1) for the internal vantage
                // from this measurement — only the runner can time its own segment.
                resultJson = WithElapsedMs(resultJson, probeWatch.Elapsed.TotalMilliseconds);
                success = true; // probe outcome (incl. failures) is data, not a job failure
                steps.Add(new { step = "PreCheck", success = true, safeLog = "probe executed from runner segment" });
            }
            else if (job.JobType == "generate-csr")
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

    /// <summary>
    /// Negotiated cipher suite for the internal vantage (§6.2). Unsupported on some platforms,
    /// where its absence is simply reported as null.
    /// </summary>
    private static string? CipherSuiteName(System.Net.Security.SslStream ssl)
    {
        try
        {
            return ssl.IsAuthenticated ? ssl.NegotiatedCipherSuite.ToString() : null;
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Adds the measured duration to a probe result document.</summary>
    private static string WithElapsedMs(string json, double elapsedMs)
    {
        try
        {
            var node = System.Text.Json.Nodes.JsonNode.Parse(json)?.AsObject();
            if (node is null) return json;
            node["elapsedMs"] = Math.Round(elapsedMs, 1);
            return node.ToJsonString();
        }
        catch
        {
            return json;
        }
    }

    /// <summary>
    /// TLS probe executed from inside the runner's segment (internal-DNS endpoints).
    /// Captures the presented leaf + chain without enforcing trust; results flow back
    /// to the control plane's inventory correlation.
    /// </summary>
    private static async Task<string> ProbeEndpointAsync(JsonElement e, CancellationToken ct)
    {
        var host = e.GetProperty("host").GetString()!;
        var port = e.GetProperty("port").GetInt32();
        var sni = e.TryGetProperty("sni", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;

        byte[]? leafDer = null;
        var chainDer = new List<byte[]>();
        bool? hostnameValid = null, chainValid = null;
        string? chainError = null;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
            using var tcp = new System.Net.Sockets.TcpClient();
            try
            {
                await tcp.ConnectAsync(host, port, timeoutCts.Token);
            }
            catch (System.Net.Sockets.SocketException ex) when (ex.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound)
            {
                return JsonSerializer.Serialize(new { status = "DnsResolutionFailed", error = ex.Message });
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                return JsonSerializer.Serialize(new { status = "ConnectionFailed", error = ex.Message });
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return JsonSerializer.Serialize(new { status = "Timeout", error = $"TCP connect to {host}:{port} timed out" });
            }

            await using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false,
                (_, cert, chain, errors) =>
                {
                    if (cert is not null)
                    {
                        leafDer = cert.GetRawCertData();
                        if (chain is not null)
                            foreach (var el in chain.ChainElements.Skip(1)) chainDer.Add(el.Certificate.RawData);
                    }
                    hostnameValid = !errors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch);
                    chainValid = !errors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)
                                 && !errors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable);
                    if (chainValid == false && chain is not null)
                        chainError = string.Join("; ", chain.ChainStatus.Select(x => x.StatusInformation.Trim()).Distinct());
                    return true;
                });
            try
            {
                await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
                {
                    TargetHost = string.IsNullOrWhiteSpace(sni) ? host : sni
                }, timeoutCts.Token);
            }
            catch (System.Security.Authentication.AuthenticationException ex) when (leafDer is null)
            {
                return JsonSerializer.Serialize(new { status = "TlsHandshakeFailed", error = ex.GetBaseException().Message });
            }
            catch (System.Security.Authentication.AuthenticationException) { /* cert captured despite handshake failure */ }

            return JsonSerializer.Serialize(new
            {
                status = "Success",
                leafDerBase64 = leafDer is null ? null : Convert.ToBase64String(leafDer),
                chainDerBase64 = chainDer.Select(Convert.ToBase64String).ToArray(),
                tlsProtocol = ssl.IsAuthenticated ? ssl.SslProtocol.ToString() : null,
                cipherSuite = CipherSuiteName(ssl),
                hostnameValid,
                chainValid,
                chainError
            });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { status = "ConnectionFailed", error = ex.GetBaseException().Message });
        }
    }

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
