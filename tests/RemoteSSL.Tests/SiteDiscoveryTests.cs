using RemoteSSL.Adapters.Discovery;

namespace RemoteSSL.Tests;

/// <summary>
/// Reading what a target actually serves (design doc §9.1 discover).
///
/// The question these answer is the one an operator has when a wildcard is about to expire: not
/// "which certificate files exist on this box" but "which of my sites is still on the old one".
/// The parsing is what makes that answerable, so it is what is tested.
/// </summary>
public class NginxConfigReaderTests
{
    /// <summary>An <c>nginx -T</c> dump of the shape the runner really gets back.</summary>
    private const string Dump = """
        # configuration file /etc/nginx/nginx.conf:
        http {
            server {
                listen 80;
                server_name ozgur.com www.ozgur.com;
                return 301 https://$host$request_uri;
            }

            server {
                listen 443 ssl http2;
                server_name www.ozgur.com;
                ssl_certificate     /etc/nginx/ssl/wildcard.crt;
                ssl_certificate_key /etc/nginx/ssl/wildcard.key;

                location / {
                    proxy_pass http://backend;
                }
            }

            server {
                listen 8443 ssl;
                server_name api.ozgur.com;
                ssl_certificate /etc/nginx/ssl/api.crt;
            }
        }
        """;

    [Fact]
    public void Only_the_server_blocks_that_serve_tls_come_back()
    {
        var servers = NginxConfigReader.Parse(Dump);

        // The plain-HTTP redirect block has no certificate, so there is nothing to replace on it.
        Assert.Equal(2, servers.Count);
        Assert.DoesNotContain(servers, s => s.ServerName == "ozgur.com");
    }

    [Fact]
    public void Each_site_carries_the_certificate_it_actually_uses()
    {
        var servers = NginxConfigReader.Parse(Dump);

        var www = servers.Single(s => s.ServerName == "www.ozgur.com");
        Assert.Equal("/etc/nginx/ssl/wildcard.crt", www.CertificatePath);
        Assert.Equal("443 ssl http2", www.Listen);

        var api = servers.Single(s => s.ServerName == "api.ozgur.com");
        Assert.Equal("/etc/nginx/ssl/api.crt", api.CertificatePath);
    }

    [Fact]
    public void The_key_path_comes_back_too_so_a_replacement_reuses_the_files_in_use()
    {
        // Replacing a certificate means writing over the exact pair this server block loads. A
        // convention like /etc/nginx/ssl/<name>.key is a guess; ssl_certificate_key is the answer.
        var servers = NginxConfigReader.Parse(Dump);

        Assert.Equal("/etc/nginx/ssl/wildcard.key", servers.Single(s => s.ServerName == "www.ozgur.com").KeyPath);
        // A block that names no key still reports the certificate rather than being dropped.
        Assert.Null(servers.Single(s => s.ServerName == "api.ozgur.com").KeyPath);
    }

    [Fact]
    public void A_directive_inside_a_nested_block_is_not_mistaken_for_the_server_s_own()
    {
        // `location` blocks routinely carry their own directives; attributing one of those to the
        // server would point a replacement at the wrong file.
        var servers = NginxConfigReader.Parse("""
            server {
                listen 443 ssl;
                server_name real.example.com;
                ssl_certificate /etc/ssl/real.crt;
                location /old {
                    server_name decoy.example.com;
                    ssl_certificate /etc/ssl/decoy.crt;
                }
            }
            """);

        var server = Assert.Single(servers);
        Assert.Equal("real.example.com", server.ServerName);
        Assert.Equal("/etc/ssl/real.crt", server.CertificatePath);
    }

    [Fact]
    public void A_server_block_with_no_name_is_still_reported_rather_than_dropped()
    {
        // The default server has no server_name but is the one answering unmatched requests —
        // exactly the one people forget during a renewal.
        var servers = NginxConfigReader.Parse("""
            server {
                listen 443 ssl default_server;
                ssl_certificate /etc/ssl/default.crt;
            }
            """);

        Assert.Equal("(default server)", Assert.Single(servers).ServerName);
    }

    [Fact]
    public void The_first_name_of_a_multi_name_server_identifies_it()
    {
        var servers = NginxConfigReader.Parse("""
            server {
                listen 443 ssl;
                server_name  primary.example.com  alias.example.com  another.example.com;
                ssl_certificate /etc/ssl/multi.crt;
            }
            """);

        Assert.Equal("primary.example.com", Assert.Single(servers).ServerName);
    }

    [Fact]
    public void An_empty_or_certificate_free_configuration_yields_nothing_rather_than_throwing()
    {
        Assert.Empty(NginxConfigReader.Parse(""));
        Assert.Empty(NginxConfigReader.Parse("server { listen 80; server_name plain.example.com; }"));
    }
}

public class OpensslSummaryTests
{
    [Fact]
    public void The_three_lines_openssl_prints_become_a_subject_an_expiry_and_a_thumbprint()
    {
        var (subject, notAfter, thumbprint) = SiteDiscovery.ParseOpensslSummary("""
            subject=CN = *.ozgur.com
            notAfter=Dec 16 09:22:41 2026 GMT
            sha256 Fingerprint=88:F0:10:C1:77:C8:23:AF:DE:E4:B6:52:BB:04:07:96:63:BF:97:CF:30:85:31:BE:68:A2:2B:5A:58:0D:1B:EF
            """);

        Assert.Equal("CN = *.ozgur.com", subject);
        Assert.Equal(2026, notAfter?.Year);
        Assert.Equal(12, notAfter?.Month);
        // Colons are how openssl prints it and not how anything else stores it.
        Assert.Equal("88F010C177C823AFDEE4B652BB04079663BF97CF308531BE68A22B5A580D1BEF", thumbprint);
    }

    [Fact]
    public void Output_from_a_file_that_is_not_a_certificate_yields_nulls_rather_than_nonsense()
    {
        var (subject, notAfter, thumbprint) = SiteDiscovery.ParseOpensslSummary("unable to load certificate");

        Assert.Null(subject);
        Assert.Null(notAfter);
        Assert.Null(thumbprint);
    }
}
