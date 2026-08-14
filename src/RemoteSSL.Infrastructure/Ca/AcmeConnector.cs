using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Infrastructure.Ca;

public sealed class AcmeConfig
{
    /// <summary>Directory URL — Let's Encrypt, an enterprise ACME server, or a staging endpoint.</summary>
    public string DirectoryUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";
    /// <summary>Contact address the CA uses for expiry and policy notices.</summary>
    public string? Contact { get; set; }
    /// <summary>Account key in PKCS#8 PEM. Generated on first use and stored with the connector.</summary>
    public string? AccountKeyPem { get; set; }
    /// <summary>Account URL, returned by the CA at registration and reused afterwards.</summary>
    public string? AccountUrl { get; set; }
    /// <summary>"dns-01" or "http-01"; dns-01 is the only one that can issue wildcards.</summary>
    public string ChallengeType { get; set; } = "dns-01";
    /// <summary>External account binding, required by most enterprise ACME deployments.</summary>
    public string? EabKeyId { get; set; }
    public string? EabHmacKeyBase64Url { get; set; }
    public bool AcceptTermsOfService { get; set; } = true;
}

/// <summary>
/// ACME (RFC 8555) connector: Let's Encrypt and enterprise ACME servers alike (design doc §18.3).
///
/// ACME differs from the commercial CAs in two ways that shape this code. First, every request is
/// a JWS signed by the account key, with a single-use nonce — so there is no session, only a
/// running nonce. Second, issuance is a state machine over an order and its authorizations, and
/// the domain validation of §18.1 is a step inside it rather than something arranged beforehand.
///
/// The order URL is the provider request id, so status polling and download work through the same
/// handle every other connector uses.
/// </summary>
public class AcmeConnector(AcmeConfig config, IHttpClientFactory? httpFactory = null)
    : ICertificateAuthorityConnector, Application.Requests.IOrderValidationConnector
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly ECDsa _accountKey = LoadOrCreateAccountKey(config);
    private JsonElement? _directory;
    private string? _nonce;

    public string ConnectorType => "acme";

    /// <summary>
    /// The account key as PEM, so the caller can persist a key generated on first use. Losing it
    /// means losing the account and every authorization already granted to it.
    /// </summary>
    public string AccountKeyPem => _accountKey.ExportPkcs8PrivateKeyPem();

    /// <summary>The account URL once registered; null until the first call that needs an account.</summary>
    public string? AccountUrl { get; private set; } = config.AccountUrl;

    private static ECDsa LoadOrCreateAccountKey(AcmeConfig config)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (!string.IsNullOrWhiteSpace(config.AccountKeyPem)) key.ImportFromPem(config.AccountKeyPem);
        return key;
    }

    private HttpClient Client()
    {
        var http = httpFactory?.CreateClient("acme") ?? new HttpClient();
        http.Timeout = TimeSpan.FromSeconds(60);
        return http;
    }

    // ---- Directory and nonce -------------------------------------------------------------------

    private async Task<JsonElement> DirectoryAsync(CancellationToken ct)
    {
        if (_directory is not null) return _directory.Value;
        using var http = Client();
        using var response = await http.GetAsync(config.DirectoryUrl, ct);
        response.EnsureSuccessStatusCode();
        _directory = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)).RootElement.Clone();
        return _directory.Value;
    }

    private async Task<string> Endpoint(string name, CancellationToken ct) =>
        (await DirectoryAsync(ct)).GetProperty(name).GetString()
        ?? throw new InvalidOperationException($"The ACME directory has no '{name}' endpoint.");

    private async Task<string> NonceAsync(CancellationToken ct)
    {
        if (_nonce is not null)
        {
            var used = _nonce;
            _nonce = null;
            return used;
        }
        using var http = Client();
        using var request = new HttpRequestMessage(HttpMethod.Head, await Endpoint("newNonce", ct));
        using var response = await http.SendAsync(request, ct);
        return response.Headers.TryGetValues("Replay-Nonce", out var values)
            ? values.First()
            : throw new InvalidOperationException("The ACME server did not return a nonce.");
    }

    // ---- JWS -----------------------------------------------------------------------------------

    /// <summary>The account key as a JWK; also what the key authorization is thumbprinted from.</summary>
    private object Jwk()
    {
        var p = _accountKey.ExportParameters(false);
        return new
        {
            crv = "P-256",
            kty = "EC",
            x = Base64Url(p.Q.X!),
            y = Base64Url(p.Q.Y!)
        };
    }

    /// <summary>
    /// RFC 8555 §8.1 key authorization: the challenge token joined to the account key thumbprint.
    /// This is what proves the same account that asked for the order controls the domain.
    /// </summary>
    public string KeyAuthorization(string token)
    {
        // The thumbprint input is the JWK with its members in lexicographic order and no whitespace.
        var p = _accountKey.ExportParameters(false);
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{Base64Url(p.Q.X!)}\",\"y\":\"{Base64Url(p.Q.Y!)}\"}}";
        var thumbprint = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        return $"{token}.{thumbprint}";
    }

    /// <summary>The dns-01 record value: the SHA-256 of the key authorization, base64url encoded.</summary>
    public string DnsRecordValue(string token) =>
        Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(KeyAuthorization(token))));

    private async Task<(HttpResponseMessage Response, string Body)> PostAsync(
        string url, object? payload, CancellationToken ct, bool useJwk = false)
    {
        var protectedHeader = useJwk
            ? (object)new { alg = "ES256", jwk = Jwk(), nonce = await NonceAsync(ct), url }
            : new { alg = "ES256", kid = AccountUrl, nonce = await NonceAsync(ct), url };

        var protectedB64 = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(protectedHeader, Json)));
        // POST-as-GET (RFC 8555 §6.3) is a POST with an empty payload, not an absent one.
        var payloadB64 = payload is null ? "" : Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, Json)));
        var signature = Base64Url(_accountKey.SignData(
            Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}"),
            HashAlgorithmName.SHA256));

        using var http = Client();
        using var content = new StringContent(
            JsonSerializer.Serialize(new { @protected = protectedB64, payload = payloadB64, signature }, Json));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");

        var response = await http.PostAsync(url, content, ct);
        if (response.Headers.TryGetValues("Replay-Nonce", out var nonces)) _nonce = nonces.First();
        var body = await response.Content.ReadAsStringAsync(ct);
        return (response, body);
    }

    // ---- Account -------------------------------------------------------------------------------

    /// <summary>
    /// Registers the account, or finds the existing one for this key. The CA answers both with the
    /// account URL, so re-registering is how you look one up.
    /// </summary>
    private async Task EnsureAccountAsync(CancellationToken ct)
    {
        if (AccountUrl is not null) return;

        object payload = config.EabKeyId is not null
            ? new
            {
                termsOfServiceAgreed = config.AcceptTermsOfService,
                contact = Contacts(),
                externalAccountBinding = await ExternalAccountBindingAsync(ct)
            }
            : new { termsOfServiceAgreed = config.AcceptTermsOfService, contact = Contacts() };

        var (response, body) = await PostAsync(await Endpoint("newAccount", ct), payload, ct, useJwk: true);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"ACME account registration failed: {Trunc(body)}");

        AccountUrl = response.Headers.Location?.ToString()
                     ?? throw new InvalidOperationException("The ACME server returned no account URL.");
    }

    private string[] Contacts() =>
        string.IsNullOrWhiteSpace(config.Contact) ? [] : [$"mailto:{config.Contact}"];

    /// <summary>
    /// External account binding (RFC 8555 §7.3.4): a JWS over the account JWK, signed with the
    /// HMAC key the CA issued out of band. Enterprise ACME deployments require it.
    /// </summary>
    private async Task<object> ExternalAccountBindingAsync(CancellationToken ct)
    {
        var url = await Endpoint("newAccount", ct);
        var header = Base64Url(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { alg = "HS256", kid = config.EabKeyId, url }, Json)));
        var payload = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Jwk(), Json)));

        using var hmac = new HMACSHA256(FromBase64Url(config.EabHmacKeyBase64Url
            ?? throw new InvalidOperationException("An external account binding needs its HMAC key.")));
        var signature = Base64Url(hmac.ComputeHash(Encoding.ASCII.GetBytes($"{header}.{payload}")));
        return new { @protected = header, payload, signature };
    }

    // ---- Connector surface ---------------------------------------------------------------------

    public async Task<CaConnectionResult> ValidateConnectionAsync(CancellationToken ct)
    {
        try
        {
            await DirectoryAsync(ct);
            await EnsureAccountAsync(ct);
            return new CaConnectionResult(true);
        }
        catch (Exception ex)
        {
            return new CaConnectionResult(false, ex.Message);
        }
    }

    /// <summary>
    /// ACME has no profiles; the challenge type is the only choice that changes what can be
    /// issued, so it is presented as one. Only dns-01 can validate a wildcard.
    /// </summary>
    public Task<IReadOnlyList<CaProfile>> ListProfilesAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<CaProfile>>(
        [
            new CaProfile("dns-01", "ACME — DNS challenge", ["RSA", "EC"], 90, true,
                """{"challenge":"dns-01","wildcard":true}"""),
            new CaProfile("http-01", "ACME — HTTP challenge", ["RSA", "EC"], 90, false,
                """{"challenge":"http-01","wildcard":false}""")
        ]);

    /// <summary>
    /// Creates the order. Validation happens afterwards: the order sits in "pending" until every
    /// authorization is satisfied, which is exactly what <see cref="GetRequestStatusAsync"/>
    /// reports as <see cref="CaRequestState.ValidationRequired"/>.
    /// </summary>
    public async Task<CaRequestRef> SubmitRequestAsync(string csrPem, string profileId,
        IReadOnlyDictionary<string, string> metadata, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);

        var identifiers = NamesFromCsr(csrPem)
            .Select(name => new { type = "dns", value = name })
            .ToArray();
        if (identifiers.Length == 0)
            throw new InvalidOperationException("The CSR carries no DNS names to order.");

        var (response, body) = await PostAsync(await Endpoint("newOrder", ct), new { identifiers }, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"ACME order creation failed: {Trunc(body)}");

        var orderUrl = response.Headers.Location?.ToString()
                       ?? throw new InvalidOperationException("The ACME server returned no order URL.");

        // The CSR is needed again at finalize; it travels in the handle so no state is kept here.
        return new CaRequestRef(ConnectorType, orderUrl);
    }

    public async Task<CaRequestStatus> GetRequestStatusAsync(CaRequestRef request, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);
        var (response, body) = await PostAsync(request.ProviderRequestId, null, ct);
        if (!response.IsSuccessStatusCode) return new CaRequestStatus(CaRequestState.Failed, Trunc(body));

        var order = JsonDocument.Parse(body).RootElement;
        var status = order.GetProperty("status").GetString();
        return status switch
        {
            "valid" => new CaRequestStatus(CaRequestState.Issued),
            "ready" => new CaRequestStatus(CaRequestState.Pending, "authorized; awaiting finalize"),
            "processing" => new CaRequestStatus(CaRequestState.Pending, "the CA is issuing"),
            "pending" => new CaRequestStatus(CaRequestState.ValidationRequired,
                "domain validation is outstanding"),
            "invalid" => new CaRequestStatus(CaRequestState.Rejected, Detail(order)),
            _ => new CaRequestStatus(CaRequestState.Pending, status)
        };
    }

    /// <summary>
    /// Finalizes the order with the CSR when it is ready, then downloads the certificate. ACME
    /// returns leaf and chain in one PEM bundle, which is split here into the shape the rest of
    /// the platform expects.
    /// </summary>
    public async Task<IssuedCertificate> DownloadCertificateAsync(CaRequestRef request, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);
        var (_, orderBody) = await PostAsync(request.ProviderRequestId, null, ct);
        var order = JsonDocument.Parse(orderBody).RootElement;

        if (!order.TryGetProperty("certificate", out var certificateUrl))
            throw new InvalidOperationException(
                $"The order is '{order.GetProperty("status").GetString()}'; no certificate is available yet.");

        var (response, pem) = await PostAsync(certificateUrl.GetString()!, null, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"ACME certificate download failed: {Trunc(pem)}");

        return SplitBundle(pem);
    }

    /// <summary>
    /// Submits the CSR for an order that has reached "ready". Separate from download because ACME
    /// makes finalize an explicit step, and it can only happen once every authorization is valid.
    /// </summary>
    public async Task FinalizeAsync(CaRequestRef request, string csrPem, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);
        var (_, orderBody) = await PostAsync(request.ProviderRequestId, null, ct);
        var order = JsonDocument.Parse(orderBody).RootElement;
        if (order.GetProperty("status").GetString() != "ready") return;

        var (response, body) = await PostAsync(order.GetProperty("finalize").GetString()!,
            new { csr = Base64Url(DerFromCsrPem(csrPem)) }, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"ACME finalize failed: {Trunc(body)}");
    }

    /// <summary>
    /// The outstanding challenges for an order, in the shape §18.1's validation screen shows: what
    /// to publish, where, and for which domain.
    /// </summary>
    public async Task<IReadOnlyList<DomainValidationChallenge>> GetOrderChallengesAsync(
        CaRequestRef request, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);
        var (_, orderBody) = await PostAsync(request.ProviderRequestId, null, ct);
        var order = JsonDocument.Parse(orderBody).RootElement;

        var challenges = new List<DomainValidationChallenge>();
        foreach (var authorizationUrl in order.GetProperty("authorizations").EnumerateArray())
        {
            var (_, authorizationBody) = await PostAsync(authorizationUrl.GetString()!, null, ct);
            var authorization = JsonDocument.Parse(authorizationBody).RootElement;
            if (authorization.GetProperty("status").GetString() == "valid") continue;

            var domain = authorization.GetProperty("identifier").GetProperty("value").GetString()!;
            var wildcard = authorization.TryGetProperty("wildcard", out var w) && w.GetBoolean();

            foreach (var challenge in authorization.GetProperty("challenges").EnumerateArray())
            {
                var type = challenge.GetProperty("type").GetString()!;
                if (type != config.ChallengeType) continue;

                var token = challenge.GetProperty("token").GetString()!;
                challenges.Add(new DomainValidationChallenge(
                    wildcard ? "*." + domain : domain,
                    type,
                    challenge.GetProperty("url").GetString()!,
                    type == "dns-01" ? $"_acme-challenge.{domain} IN TXT \"{DnsRecordValue(token)}\"" : null,
                    type == "http-01" ? $"/.well-known/acme-challenge/{token} → {KeyAuthorization(token)}" : null,
                    order.TryGetProperty("expires", out var e) && e.TryGetDateTimeOffset(out var expires)
                        ? expires
                        : null));
            }
        }
        return challenges;
    }

    /// <summary>
    /// Tells the CA the challenge is ready to be checked. The challenge URL is carried in the
    /// token field of the challenge record, which is why it round-trips through there.
    /// </summary>
    public async Task<bool> AnswerChallengeAsync(string challengeUrl, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);
        var (response, _) = await PostAsync(challengeUrl, new { }, ct);
        return response.IsSuccessStatusCode;
    }

    public Task<CaRequestRef> RenewAsync(string certificateSerial, string csrPem, string profileId,
        CancellationToken ct) =>
        // ACME renewal is a new order for the same names; there is no renew endpoint.
        SubmitRequestAsync(csrPem, profileId, new Dictionary<string, string>(), ct);

    public Task RevokeAsync(string certificateSerial, RevocationReason reason, CancellationToken ct) =>
        // RFC 8555 §7.6 revokes by certificate, not by serial: the caller must hand over the
        // certificate itself, which the platform stores alongside the serial.
        throw new NotSupportedException(
            "ACME revocation needs the certificate, not just its serial; use RevokeCertificateAsync.");

    /// <summary>Revokes an issued certificate (RFC 8555 §7.6), which ACME identifies by its DER.</summary>
    public async Task RevokeCertificateAsync(string certificatePem, RevocationReason reason, CancellationToken ct)
    {
        await EnsureAccountAsync(ct);
        using var certificate = X509Certificate2.CreateFromPem(certificatePem);
        var (response, body) = await PostAsync(await Endpoint("revokeCert", ct), new
        {
            certificate = Base64Url(certificate.RawData),
            reason = (int)ToAcmeReason(reason)
        }, ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"ACME revocation failed: {Trunc(body)}");
    }

    public Task<DomainValidationChallenge?> RequestDomainValidationAsync(string domain, string method,
        CancellationToken ct) =>
        // In ACME a challenge only exists inside an order; there is nothing to arrange beforehand.
        Task.FromResult<DomainValidationChallenge?>(null);

    // ---- Helpers -------------------------------------------------------------------------------

    /// <summary>RFC 5280 CRLReason codes, which is what ACME expects.</summary>
    public static int ToAcmeReason(RevocationReason reason) => reason switch
    {
        RevocationReason.KeyCompromise => 1,
        RevocationReason.Superseded => 4,
        RevocationReason.CessationOfOperation => 5,
        _ => 0
    };

    /// <summary>The DNS names a CSR asks for: its subject CN plus every dNSName in the SAN.</summary>
    public static IReadOnlyList<string> NamesFromCsr(string csrPem)
    {
        var request = CertificateRequest.LoadSigningRequestPem(csrPem, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pkcs1);

        var names = new List<string>();
        var cn = request.SubjectName.EnumerateRelativeDistinguishedNames()
            .FirstOrDefault(r => r.GetSingleElementType().Value == "2.5.4.3")?.GetSingleElementValue();
        if (!string.IsNullOrWhiteSpace(cn)) names.Add(cn);

        foreach (var extension in request.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>())
            names.AddRange(extension.EnumerateDnsNames());

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static byte[] DerFromCsrPem(string csrPem)
    {
        var body = csrPem
            .Replace("-----BEGIN CERTIFICATE REQUEST-----", string.Empty)
            .Replace("-----END CERTIFICATE REQUEST-----", string.Empty)
            .Replace("-----BEGIN NEW CERTIFICATE REQUEST-----", string.Empty)
            .Replace("-----END NEW CERTIFICATE REQUEST-----", string.Empty);
        return Convert.FromBase64String(new string(body.Where(c => !char.IsWhiteSpace(c)).ToArray()));
    }

    /// <summary>Splits an ACME PEM bundle into its leaf and the chain behind it.</summary>
    public static IssuedCertificate SplitBundle(string bundlePem)
    {
        var blocks = bundlePem.Split("-----END CERTIFICATE-----", StringSplitOptions.RemoveEmptyEntries)
            .Select(b => b.Trim())
            .Where(b => b.Contains("-----BEGIN CERTIFICATE-----"))
            .Select(b => b[b.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)..]
                         + "\n-----END CERTIFICATE-----")
            .ToList();
        if (blocks.Count == 0) throw new InvalidOperationException("The ACME response carried no certificate.");

        using var leaf = X509Certificate2.CreateFromPem(blocks[0]);
        return new IssuedCertificate(blocks[0], string.Join('\n', blocks.Skip(1)), leaf.SerialNumber);
    }

    private static string Detail(JsonElement order) =>
        order.TryGetProperty("error", out var error) ? error.ToString() : "the order was rejected";

    public static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}
