using System.Text.Json;
using System.Text.RegularExpressions;
using RemoteSSL.Adapters.Ssh;
using RemoteSSL.Adapters.Windows;

namespace RemoteSSL.Adapters.Discovery;

/// <summary>
/// One place on a target that serves a certificate, and which certificate it is serving right now
/// (design doc §9.1 <c>discover</c>).
///
/// Deployment used to start from a path: you told RemoteSSL where to write and it wrote there.
/// That is the wrong end of the question. What an operator has is a wildcard about to expire and
/// an IIS server with nine sites on it — and what they need to know is which of those sites is on
/// the old certificate. Listing the files under /etc/ssl does not answer that; the binding does.
/// </summary>
/// <param name="Kind">"iis-site", "nginx-server", "windows-store", "keystore-alias".</param>
/// <param name="Name">What the operator calls it: the site name, the server_name, the alias.</param>
/// <param name="Detail">Where it listens or lives — the binding, the config file, the store path.</param>
/// <param name="Thumbprint">SHA-1 for Windows bindings, SHA-256 elsewhere; null when nothing is bound.</param>
/// <param name="StorePath">What a CertificateStore for this site would point at, when that is known.</param>
public sealed record DiscoveredSite(
    string Kind,
    string Name,
    string? Detail = null,
    string? Thumbprint = null,
    string? Subject = null,
    DateTimeOffset? NotAfter = null,
    string? StorePath = null,
    string? Alias = null);

public sealed record SiteDiscoveryResult(
    bool Success,
    IReadOnlyList<DiscoveredSite> Sites,
    string? Error = null,
    /// <summary>Set when the adapter has no site-level discovery yet, so the UI can say why.</summary>
    string? NotSupportedReason = null);

public static class SiteDiscovery
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Lists IIS sites with their HTTPS bindings and the certificate each one currently serves.
    /// Emitted as JSON rather than a formatted table so the answer survives locale and column
    /// widths — a discovery that has to be screen-scraped is one that breaks on someone's server.
    /// </summary>
    public const string IisScript = """
        $ErrorActionPreference = 'Stop'
        Import-Module WebAdministration
        $store = @{}
        Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { $store[$_.Thumbprint] = $_ }
        $out = @()
        foreach ($site in Get-Website) {
          foreach ($b in $site.Bindings.Collection) {
            if ($b.protocol -ne 'https') { continue }
            $tp = ''
            if ($b.certificateHash) { $tp = ($b.certificateHash | ForEach-Object { $_.ToString('X2') }) -join '' }
            $c = $null
            if ($tp -and $store.ContainsKey($tp)) { $c = $store[$tp] }
            $out += [pscustomobject]@{
              kind       = 'iis-site'
              name       = $site.name
              detail     = $b.bindingInformation
              thumbprint = $tp
              subject    = $(if ($c) { $c.Subject } else { $null })
              notAfter   = $(if ($c) { $c.NotAfter.ToString('o') } else { $null })
              storePath  = $(if ($b.certificateStoreName) { 'LocalMachine/' + $b.certificateStoreName } else { 'LocalMachine/My' })
            }
          }
        }
        ConvertTo-Json -InputObject @($out) -Compress -Depth 3
        """;

    /// <summary>Everything in LocalMachine\My, for a Windows target that is not running IIS.</summary>
    public const string WindowsStoreScript = """
        $ErrorActionPreference = 'Stop'
        $out = Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
          [pscustomobject]@{
            kind       = 'windows-store'
            name       = $(if ($_.FriendlyName) { $_.FriendlyName } else { $_.Subject })
            detail     = 'LocalMachine\My'
            thumbprint = $_.Thumbprint
            subject    = $_.Subject
            notAfter   = $_.NotAfter.ToString('o')
            storePath  = 'LocalMachine/My'
          }
        }
        ConvertTo-Json -InputObject @($out) -Compress -Depth 3
        """;

    public static SiteDiscoveryResult DiscoverWindows(IWindowsChannel channel, bool iis)
    {
        var result = channel.RunPs(iis ? IisScript : WindowsStoreScript, TimeSpan.FromMinutes(2));
        if (!result.Ok)
            return new SiteDiscoveryResult(false, [], result.Stderr.Trim());

        try
        {
            var sites = JsonSerializer.Deserialize<List<PsSite>>(result.Stdout.Trim(), Json) ?? [];
            return new SiteDiscoveryResult(true, sites.Select(s => s.ToSite()).ToList());
        }
        catch (JsonException ex)
        {
            return new SiteDiscoveryResult(false, [], $"the target's reply could not be read: {ex.Message}");
        }
    }

    private sealed record PsSite(
        string? Kind, string? Name, string? Detail, string? Thumbprint,
        string? Subject, string? NotAfter, string? StorePath)
    {
        public DiscoveredSite ToSite() => new(
            Kind ?? "windows-store",
            string.IsNullOrWhiteSpace(Name) ? "(unnamed)" : Name,
            Detail,
            string.IsNullOrWhiteSpace(Thumbprint) ? null : Thumbprint,
            Subject,
            DateTimeOffset.TryParse(NotAfter, out var d) ? d : null,
            StorePath);
    }

    /// <summary>
    /// Lists nginx server blocks and the certificate file each one uses, then reads those files to
    /// say what is actually in them. <c>nginx -T</c> is the only reliable source: it prints the
    /// configuration nginx really loaded, includes resolved and all.
    /// </summary>
    public static SiteDiscoveryResult DiscoverNginx(SshConnection ssh)
    {
        var dump = ssh.Exec("nginx -T 2>/dev/null || sudo nginx -T 2>/dev/null", TimeSpan.FromMinutes(1));
        if (string.IsNullOrWhiteSpace(dump.Stdout))
            return new SiteDiscoveryResult(false, [],
                "nginx -T produced nothing — is nginx installed, and may this account run it?");

        var servers = NginxConfigReader.Parse(dump.Stdout);
        if (servers.Count == 0)
            return new SiteDiscoveryResult(true, []);

        // One read per distinct certificate file rather than per server block: several server
        // blocks routinely share one certificate, and this is a wildcard's whole point.
        var details = new Dictionary<string, (string? Subject, DateTimeOffset? NotAfter, string? Thumbprint)>();
        foreach (var path in servers.Select(s => s.CertificatePath).Distinct())
        {
            if (string.IsNullOrWhiteSpace(path)) continue;
            var read = ssh.Exec(
                $"openssl x509 -in {Shell.Quote(path)} -noout -subject -enddate -fingerprint -sha256 2>/dev/null");
            if (!read.Ok) continue;
            details[path] = ParseOpensslSummary(read.Stdout);
        }

        var sites = servers.Select(s =>
        {
            details.TryGetValue(s.CertificatePath ?? "", out var d);
            return new DiscoveredSite(
                "nginx-server",
                s.ServerName,
                s.Listen is null ? s.CertificatePath : $"listen {s.Listen} · {s.CertificatePath}",
                d.Thumbprint, d.Subject, d.NotAfter,
                // The store for an nginx server block is the directory its certificate lives in.
                s.CertificatePath is null ? null : DirectoryOf(s.CertificatePath));
        }).ToList();

        return new SiteDiscoveryResult(true, sites);
    }

    private static string DirectoryOf(string path)
    {
        var i = path.LastIndexOf('/');
        return i <= 0 ? path : path[..i];
    }

    /// <summary>Reads the four lines openssl prints for -subject -enddate -fingerprint.</summary>
    public static (string? Subject, DateTimeOffset? NotAfter, string? Thumbprint) ParseOpensslSummary(string output)
    {
        string? subject = null, thumbprint = null;
        DateTimeOffset? notAfter = null;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("subject=", StringComparison.OrdinalIgnoreCase))
                subject = trimmed["subject=".Length..].Trim();
            else if (trimmed.StartsWith("notAfter=", StringComparison.OrdinalIgnoreCase))
                notAfter = ParseOpensslDate(trimmed["notAfter=".Length..].Trim());
            else if (trimmed.Contains("Fingerprint=", StringComparison.OrdinalIgnoreCase))
                thumbprint = trimmed.Split('=').Last().Replace(":", "").Trim();
        }

        return (subject, notAfter, thumbprint);
    }

    /// <summary>
    /// openssl prints "Dec 16 09:22:41 2026 GMT", and pads a single-digit day with a second space
    /// ("Dec  6 …"). Neither shape is something the general parser recognises, so the formats are
    /// spelled out; anything unexpected returns null rather than a plausible wrong date.
    /// </summary>
    private static DateTimeOffset? ParseOpensslDate(string value)
    {
        string[] formats = ["MMM d HH:mm:ss yyyy 'GMT'", "MMM  d HH:mm:ss yyyy 'GMT'", "MMM dd HH:mm:ss yyyy 'GMT'"];
        return DateTimeOffset.TryParseExact(value, formats,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var exact)
            ? exact
            : DateTimeOffset.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal, out var loose)
                ? loose
                : null;
    }
}

/// <summary>
/// Pulls server blocks out of an <c>nginx -T</c> dump. Deliberately a small, brace-counting
/// reader rather than a general nginx parser: it only has to find which name is served where and
/// with which certificate, and a full grammar would be a great deal of code to get the same two
/// directives.
/// </summary>
public static class NginxConfigReader
{
    public sealed record NginxServer(string ServerName, string? Listen, string? CertificatePath);

    private static readonly Regex ServerStart = new(@"^\s*server\s*\{", RegexOptions.Compiled);
    private static readonly Regex Directive = new(@"^\s*(server_name|listen|ssl_certificate)\s+([^;]+);",
        RegexOptions.Compiled);

    public static IReadOnlyList<NginxServer> Parse(string dump)
    {
        var servers = new List<NginxServer>();
        var lines = dump.Replace("\r\n", "\n").Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            if (!ServerStart.IsMatch(lines[i])) continue;

            string? name = null, listen = null, certificate = null;
            // Depth starts at the brace on the `server {` line itself.
            var depth = 1;
            for (var j = i + 1; j < lines.Length && depth > 0; j++)
            {
                var line = lines[j];
                // A nested block (location, if) may carry its own listen; only the server's own
                // directives count, so anything deeper is skipped rather than misattributed.
                if (depth == 1)
                {
                    var m = Directive.Match(line);
                    if (m.Success)
                    {
                        var value = m.Groups[2].Value.Trim();
                        switch (m.Groups[1].Value)
                        {
                            // "server_name a.example.com b.example.com" — the first is the identity.
                            case "server_name": name ??= value.Split(' ', StringSplitOptions.RemoveEmptyEntries).First(); break;
                            case "listen": listen ??= value; break;
                            case "ssl_certificate": certificate ??= value; break;
                        }
                    }
                }

                depth += line.Count(c => c == '{') - line.Count(c => c == '}');
            }

            // A server block with no TLS is not a place a certificate can be replaced.
            if (certificate is not null)
                servers.Add(new NginxServer(name ?? "(default server)", listen, certificate));
        }

        return servers;
    }
}
