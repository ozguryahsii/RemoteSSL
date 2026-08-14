using RemoteSSL.Adapters.Java;
using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Windows;
using RemoteSSL.Application.Deployments;

namespace RemoteSSL.Tests;

/// <summary>The adapter capability catalog — design doc §9.3.</summary>
public class AdapterCatalogTests
{
    [Fact]
    public void Every_adapter_the_payload_builder_knows_is_in_the_catalog()
    {
        // The catalog is what the UI offers; an adapter missing from it would be unreachable, and
        // one present but unbuildable would fail only at deployment time.
        string[] built =
        [
            "nginx", "apache", "haproxy", "generic-file", "generic-ssh",
            "windows-cert-store", "iis", "windows-ccs",
            "java-keystore", "java-truststore", "oracle-wallet",
            "f5-bigip", "fortigate", "paloalto", "citrix-adc", "cisco-ise"
        ];

        Assert.Equal(built.Order(), AdapterCatalog.All.Select(a => a.Type).Order());
    }

    [Fact]
    public void An_adapter_that_replaces_the_certificate_in_place_reports_no_rollback()
    {
        Assert.False(AdapterCatalog.SupportsRollback("cisco-ise"));
        Assert.True(AdapterCatalog.SupportsRollback("f5-bigip"));
    }

    [Fact]
    public void A_truststore_does_not_need_the_private_key()
    {
        Assert.False(AdapterCatalog.RequiresPrivateKey("java-truststore"));
        Assert.False(AdapterCatalog.RequiresPrivateKey("oracle-wallet"));
        Assert.True(AdapterCatalog.RequiresPrivateKey("nginx"));
    }

    [Fact]
    public void The_devices_that_keep_a_candidate_configuration_are_flagged_as_needing_a_commit()
    {
        Assert.True(AdapterCatalog.Find("paloalto")!.RequiresCommit);
        Assert.True(AdapterCatalog.Find("citrix-adc")!.RequiresCommit);
        Assert.False(AdapterCatalog.Find("fortigate")!.RequiresCommit);
    }

    [Fact]
    public void An_unknown_adapter_is_reported_rather_than_silently_defaulted()
    {
        Assert.Null(AdapterCatalog.Find("not-an-adapter"));
    }

    [Fact]
    public void Every_descriptor_names_a_host_or_a_management_url()
    {
        foreach (var adapter in AdapterCatalog.All)
        {
            Assert.NotEmpty(adapter.DisplayName);
            Assert.Contains(adapter.Channel, new[] { "ssh", "winrm", "rest" });
            Assert.Contains(adapter.ConnectionFields, f => f.Key is "host" or "managementUrl");
        }
    }

    [Fact]
    public void Required_fields_are_marked_so_a_form_can_enforce_them()
    {
        Assert.Contains(AdapterCatalog.Find("nginx")!.ServiceFields, f => f.Key == "certPath" && f.Required);
        Assert.Contains(AdapterCatalog.Find("windows-ccs")!.ServiceFields, f => f.Key == "ccsPath" && f.Required);
    }
}

/// <summary>Generic SSH template adapter — design doc §14.2.</summary>
public class GenericSshTemplateTests
{
    [Fact]
    public void A_template_substitutes_only_the_placeholders_it_knows()
    {
        var rendered = GenericSshDeployer.Render(
            "install {certPath} --key {keyPath} --id {thumbprint} --keep {unknown}",
            new Dictionary<string, string>
            {
                ["certPath"] = "/etc/ssl/a.crt",
                ["keyPath"] = "/etc/ssl/a.key",
                ["thumbprint"] = "ABC"
            });

        Assert.Equal("install /etc/ssl/a.crt --key /etc/ssl/a.key --id ABC --keep {unknown}", rendered);
    }

    [Fact]
    public void An_empty_placeholder_value_renders_as_empty_rather_than_the_literal_token()
    {
        var rendered = GenericSshDeployer.Render("cmd {chainPath}",
            new Dictionary<string, string> { ["chainPath"] = "" });

        Assert.Equal("cmd ", rendered);
    }

    [Fact]
    public void The_payload_defaults_leave_every_command_unset()
    {
        // The adapter runs nothing it was not explicitly configured to run (§14.2).
        var payload = new GenericSshPayload();
        Assert.Null(payload.InstallCmd);
        Assert.Null(payload.ValidateCmd);
        Assert.Null(payload.ReloadCmd);
        Assert.Null(payload.VerifyCmd);
        Assert.Null(payload.RollbackCmd);
    }
}

/// <summary>Windows system bindings and CCS — design doc §11.4.</summary>
public class WindowsBindingTests
{
    [Fact]
    public void The_rdp_binding_writes_the_thumbprint_into_terminal_services()
    {
        var script = WindowsDeployer.ServiceBindingScript("rdp", "ABC123")!;

        Assert.Contains("Win32_TSGeneralSetting", script);
        Assert.Contains("SSLCertificateSHA1Hash = 'ABC123'", script);
        Assert.Contains("$ts.Put()", script);
    }

    [Fact]
    public void The_winrm_binding_recreates_the_https_listener()
    {
        var script = WindowsDeployer.ServiceBindingScript("winrm", "ABC123")!;

        Assert.Contains("winrm delete", script);
        Assert.Contains("winrm create", script);
        Assert.Contains("CertificateThumbprint", script);
        Assert.Contains("ABC123", script);
    }

    [Fact]
    public void An_unknown_binding_target_produces_no_script_at_all()
    {
        // Returning null makes the deployer fail the step rather than run something unintended.
        Assert.Null(WindowsDeployer.ServiceBindingScript("smtp", "ABC123"));
    }

    [Fact]
    public void A_ccs_payload_is_recognised_by_its_share_path()
    {
        var payload = new WindowsDeployPayload { CcsPath = @"\\fileserver\certs" };

        Assert.NotNull(payload.CcsPath);
        Assert.False(payload.EnableCcs);
        Assert.True(payload.NonExportablePrivateKey);
    }
}

/// <summary>Java keystore inventory parsing — design doc §12.3.</summary>
public class JavaKeystoreInventoryTests
{
    private const string Listing = """
        Keystore type: PKCS12
        Keystore provider: SUN

        Your keystore contains 2 entries

        Alias name: tomcat
        Creation date: 4 May 2026
        Entry type: PrivateKeyEntry
        Certificate chain length: 2
        Certificate[1]:
        Owner: CN=app.example.com, O=Acme
        Issuer: CN=Acme Issuing CA, O=Acme
        Serial number: 0a1b2c3d
        Valid from: Mon May 04 10:00:00 UTC 2026 until: Sun Aug 02 10:00:00 UTC 2026
        Certificate fingerprints:
                 SHA1: AA:BB:CC
                 SHA256: 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00

        *******************************************
        *******************************************

        Alias name: acmerootca
        Creation date: 1 Jan 2020
        Entry type: trustedCertEntry

        Owner: CN=Acme Root CA, O=Acme
        Issuer: CN=Acme Root CA, O=Acme
        Serial number: 01
        Valid from: Wed Jan 01 00:00:00 UTC 2020 until: Fri Jan 01 00:00:00 UTC 2038
        Certificate fingerprints:
                 SHA256: FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00
        """;

    [Fact]
    public void Both_entries_are_found_with_their_types()
    {
        var entries = JavaKeystoreInventory.Parse(Listing);

        Assert.Equal(2, entries.Count);
        Assert.Equal("tomcat", entries[0].Alias);
        Assert.Equal("PrivateKeyEntry", entries[0].EntryType);
        Assert.Equal("acmerootca", entries[1].Alias);
        Assert.Equal("trustedCertEntry", entries[1].EntryType);
    }

    [Fact]
    public void The_subject_issuer_and_serial_come_from_the_right_entry()
    {
        var entries = JavaKeystoreInventory.Parse(Listing);

        Assert.Equal("CN=app.example.com, O=Acme", entries[0].Subject);
        Assert.Equal("CN=Acme Issuing CA, O=Acme", entries[0].Issuer);
        Assert.Equal("0a1b2c3d", entries[0].SerialNumber);
        Assert.Equal("CN=Acme Root CA, O=Acme", entries[1].Subject);
    }

    [Fact]
    public void The_sha256_fingerprint_is_normalised_to_plain_hex()
    {
        var entries = JavaKeystoreInventory.Parse(Listing);

        Assert.Equal("112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00",
            entries[0].Sha256Thumbprint);
        Assert.DoesNotContain(":", entries[1].Sha256Thumbprint);
    }

    [Fact]
    public void The_expiry_is_read_from_the_validity_line()
    {
        var entries = JavaKeystoreInventory.Parse(Listing);

        Assert.NotNull(entries[0].NotAfter);
        Assert.Equal(2026, entries[0].NotAfter!.Value.Year);
        Assert.Equal(8, entries[0].NotAfter!.Value.Month);
        Assert.Equal(2038, entries[1].NotAfter!.Value.Year);
    }

    [Fact]
    public void An_empty_keystore_yields_no_entries_rather_than_an_error()
    {
        Assert.Empty(JavaKeystoreInventory.Parse("Your keystore contains 0 entries\n"));
    }

    [Fact]
    public void An_entry_without_a_certificate_still_reports_its_alias()
    {
        // A key-only entry has no Owner line; the alias and type are still worth recording.
        var entries = JavaKeystoreInventory.Parse("Alias name: bare\nEntry type: SecretKeyEntry\n");

        Assert.Single(entries);
        Assert.Equal("bare", entries[0].Alias);
        Assert.Null(entries[0].Subject);
        Assert.Null(entries[0].NotAfter);
    }
}
