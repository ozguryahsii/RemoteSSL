using RemoteSSL.Application.Deployments;

namespace RemoteSSL.Tests;

/// <summary>
/// Naming the place a binding installs to, and refusing to invent a path for a private key.
///
/// Both come from the same problem: a certificate store is a place, not a site. Several sites can
/// share one — three IIS sites all live in LocalMachine\My — so a store alone neither identifies
/// the binding nor says where the key belongs.
/// </summary>
public class BindingSiteNameTests
{
    [Fact]
    public void An_iis_binding_is_named_by_its_site()
    {
        Assert.Equal("Default Web Site",
            DeploymentPlanner.SiteOf("""{"iisSiteName":"Default Web Site","iisPort":"443"}""", alias: null));
    }

    [Fact]
    public void A_file_binding_is_named_by_the_file_it_writes()
    {
        // Two nginx server blocks on one machine differ by this and by nothing else the plan shows.
        Assert.Equal("/etc/nginx/ssl/wildcard.crt",
            DeploymentPlanner.SiteOf("""{"certPath":"/etc/nginx/ssl/wildcard.crt"}""", alias: null));
    }

    [Fact]
    public void A_keystore_binding_falls_back_to_its_alias()
    {
        Assert.Equal("tomcat", DeploymentPlanner.SiteOf("{}", alias: "tomcat"));
    }

    [Fact]
    public void A_binding_with_nothing_to_name_it_reports_nothing_rather_than_a_guess()
    {
        Assert.Null(DeploymentPlanner.SiteOf("{}", alias: null));
        Assert.Null(DeploymentPlanner.SiteOf("not json at all", alias: null));
    }
}

public class KeyPathDerivationTests
{
    [Theory]
    [InlineData("/etc/nginx/ssl/wildcard.crt", "/etc/nginx/ssl/wildcard.key")]
    [InlineData("/etc/ssl/site.pem", "/etc/ssl/site.key")]
    [InlineData("/etc/ssl/site.cer", "/etc/ssl/site.key")]
    public void The_key_sits_beside_the_certificate_when_the_certificate_is_a_file(string cert, string key)
    {
        Assert.Equal(key, DeploymentService.DeriveKeyPath(cert));
    }

    [Fact]
    public void A_store_directory_yields_no_key_path_at_all()
    {
        // This is the bug the check exists for: the fallback used to swap an extension the store
        // path did not have, so the "key path" came out as the directory itself and `mv` dropped
        // the private key inside it under the temporary name. No path is the safe answer (§7.3) —
        // the deployment refuses instead, and the plan says so before anything is uploaded.
        Assert.Equal("", DeploymentService.DeriveKeyPath("/etc/nginx/ssl"));
        Assert.Equal("", DeploymentService.DeriveKeyPath("LocalMachine/My"));
    }
}
