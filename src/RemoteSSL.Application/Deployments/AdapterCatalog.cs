namespace RemoteSSL.Application.Deployments;

/// <summary>A configuration field an adapter needs, described well enough for a UI to render it.</summary>
/// <param name="Key">Property name inside the target's connection config or the binding's service config.</param>
/// <param name="Label">What to call it on screen.</param>
/// <param name="Help">One line explaining what the operator should put there.</param>
/// <param name="Required">Whether the adapter cannot work without it.</param>
/// <param name="Options">Fixed choices, when the field is a closed set.</param>
public sealed record AdapterField(
    string Key, string Label, string? Help = null, bool Required = false,
    IReadOnlyList<string>? Options = null, string? Default = null);

/// <summary>
/// What an adapter can and cannot do (design doc §9.3). The UI reads this instead of hard-coding
/// per-adapter behaviour, so a screen never offers an action the platform would refuse — no
/// rollback button where rollback is impossible, no alias field where there are no aliases.
/// </summary>
/// <param name="Type">The adapter id stored on the target.</param>
/// <param name="Channel">How the runner reaches the target: "ssh", "winrm", "rest".</param>
public sealed record AdapterDescriptor(
    string Type,
    string DisplayName,
    string Category,
    string Channel,
    bool RequiresPrivateKey,
    bool SupportsChain,
    bool SupportsRollback,
    bool SupportsAlias,
    bool SupportsRemoteVerify,
    bool SupportsStoreDiscovery,
    bool RequiresCommit,
    IReadOnlyList<AdapterField> ConnectionFields,
    IReadOnlyList<AdapterField> ServiceFields,
    string? Notes = null);

/// <summary>
/// The adapters this build ships, with their capabilities (§9.3). One list, read by the API, the
/// deployment planner and the UI — so what the screen offers and what the runner can actually do
/// cannot drift apart.
/// </summary>
public static class AdapterCatalog
{
    private static readonly AdapterField Host =
        new("host", "Host", "Hostname or IP the runner connects to.", Required: true);
    private static readonly AdapterField SshPort =
        new("port", "SSH port", Default: "22");
    private static readonly AdapterField UseSudo =
        new("useSudo", "Use sudo", "Run privileged steps through sudo.");
    private static readonly AdapterField ManagementUrl =
        new("managementUrl", "Management URL", "Management plane base URL — never the data plane address.", Required: true);
    private static readonly AdapterField AllowInsecureTls =
        new("allowInsecureTls", "Accept the device's current certificate",
            "Needed on first contact when the device still serves an untrusted certificate.");
    private static readonly AdapterField ReloadCmd =
        new("reloadCmd", "Reload command", "Command that makes the service pick the certificate up.");
    private static readonly AdapterField ValidateCmd =
        new("validateCmd", "Validate command", "Config test run before the reload, e.g. nginx -t.");

    public static readonly IReadOnlyList<AdapterDescriptor> All =
    [
        new("nginx", "nginx", "Linux", "ssh",
            RequiresPrivateKey: true, SupportsChain: true, SupportsRollback: true, SupportsAlias: false,
            SupportsRemoteVerify: true, SupportsStoreDiscovery: false, RequiresCommit: false,
            [Host, SshPort, UseSudo],
            [
                new("certPath", "Certificate path", Required: true),
                new("keyPath", "Private key path", Required: true),
                new("chainPath", "Chain path", "Leave empty to append the chain to the certificate file."),
                ValidateCmd, ReloadCmd,
                new("owner", "File owner", "user:group applied to the written files.")
            ]),

        new("apache", "Apache httpd", "Linux", "ssh",
            true, true, true, false, true, false, false,
            [Host, SshPort, UseSudo],
            [
                new("certPath", "Certificate path", Required: true),
                new("keyPath", "Private key path", Required: true),
                new("chainPath", "Chain path"),
                ValidateCmd, ReloadCmd, new("owner", "File owner")
            ]),

        new("haproxy", "HAProxy", "Linux", "ssh",
            true, true, true, false, true, false, false,
            [Host, SshPort, UseSudo],
            [
                new("certPath", "PEM bundle path", "HAProxy expects certificate, chain and key in one file.", true),
                new("bundleMode", "Bundle mode", Options: ["combined", "separate"], Default: "combined"),
                ValidateCmd, ReloadCmd, new("owner", "File owner")
            ]),

        new("generic-file", "Generic file drop", "Linux", "ssh",
            true, true, true, false, false, false, false,
            [Host, SshPort, UseSudo],
            [
                new("certPath", "Certificate path", Required: true),
                new("keyPath", "Private key path"),
                new("chainPath", "Chain path"),
                ReloadCmd, new("owner", "File owner")
            ],
            "Writes the files and runs the reload command; nothing about the service is assumed."),

        new("generic-ssh", "Generic SSH template", "Linux", "ssh",
            true, true, true, false, false, false, false,
            [Host, SshPort, UseSudo],
            [
                new("certPath", "Certificate path", Required: true),
                new("keyPath", "Private key path"),
                new("chainPath", "Chain path"),
                new("installCmd", "Install command template",
                    "Runs after the files are staged. Placeholders: {certPath} {keyPath} {chainPath} {thumbprint}."),
                new("validateCmd", "Validate command template"),
                new("reloadCmd", "Reload command template"),
                new("verifyCmd", "Verify command template",
                    "Must exit non-zero when the certificate did not take effect."),
                new("rollbackCmd", "Rollback command template",
                    "Runs with {backupPath} when a later step fails.")
            ],
            "The escape hatch of §14.2 for appliances with no adapter. Commands come from this "
            + "configuration only — never from a certificate, a target name or any other data."),

        new("windows-cert-store", "Windows certificate store", "Windows", "winrm",
            true, true, true, false, false, false, false,
            [
                Host,
                new("method", "Channel", "WinRM is the primary channel; SSH is the alternative.",
                    Options: ["winrm", "ssh"], Default: "winrm"),
                new("port", "Port", "Blank uses 5985/5986 for WinRM, 22 for SSH."),
                new("winRmUseSsl", "WinRM over HTTPS")
            ],
            [
                new("exportablePrivateKey", "Allow the private key to be exported",
                    "Off by default; the key is imported non-exportable."),
                new("privateKeyReadAccounts", "Private key read access",
                    "Service identities that must read the key, e.g. IIS AppPool\\Site.")
            ]),

        new("iis", "IIS", "Windows", "winrm",
            true, true, true, false, true, false, false,
            [
                Host,
                new("method", "Channel", Options: ["winrm", "ssh"], Default: "winrm"),
                new("port", "Port"),
                new("winRmUseSsl", "WinRM over HTTPS")
            ],
            [
                new("iisSiteName", "Site name", Required: true),
                new("iisHostHeader", "Host header", "Required for SNI bindings."),
                new("iisPort", "HTTPS port", Default: "443"),
                new("bindingTargets", "Also bind to", "System services to point at the same certificate.",
                    Options: ["rdp", "winrm"]),
                new("exportablePrivateKey", "Allow the private key to be exported"),
                new("privateKeyReadAccounts", "Private key read access")
            ]),

        new("windows-ccs", "Windows Centralized Certificate Store", "Windows", "winrm",
            true, true, true, false, true, false, false,
            [
                Host,
                new("method", "Channel", Options: ["winrm", "ssh"], Default: "winrm"),
                new("port", "Port"),
                new("winRmUseSsl", "WinRM over HTTPS")
            ],
            [
                new("ccsPath", "CCS share path", "UNC path IIS reads certificates from.", Required: true),
                new("ccsFileName", "File name",
                    "Defaults to the certificate's common name; CCS matches the requested host name."),
                new("enableCcs", "Enable the central certificate provider",
                    "Turns CCS on for the site if it is not already configured.")
            ],
            "IIS CCS keeps PFX files on a share named after the host they serve, so no per-server "
            + "store import is needed (§11.4)."),

        new("java-keystore", "Java keystore", "Java", "ssh",
            true, true, true, true, false, true, false,
            [Host, SshPort, UseSudo, new("storeType", "Store type", Options: ["JKS", "PKCS12"], Default: "JKS")],
            [
                new("keytoolPath", "keytool path", "Defaults to keytool on PATH."),
                ReloadCmd
            ]),

        new("java-truststore", "Java truststore", "Java", "ssh",
            false, true, true, true, false, true, false,
            [Host, SshPort, UseSudo, new("storeType", "Store type", Options: ["JKS", "PKCS12"], Default: "JKS")],
            [new("keytoolPath", "keytool path"), ReloadCmd]),

        new("oracle-wallet", "Oracle wallet", "Oracle", "ssh",
            false, true, true, false, false, false, false,
            [Host, SshPort, UseSudo],
            [
                new("orapkiPath", "orapki path"),
                new("certKind", "Certificate kind", Options: ["trusted", "user"], Default: "trusted"),
                ReloadCmd
            ]),

        new("f5-bigip", "F5 BIG-IP", "Network", "rest",
            true, true, true, true, true, false, false,
            [
                ManagementUrl,
                new("partition", "Administrative partition", "The tenant the objects belong to.", Default: "Common"),
                AllowInsecureTls
            ],
            [
                new("certObjectName", "Certificate object name", Required: true),
                new("clientSslProfile", "Client SSL profile", "The profile re-pointed at the new certificate.", true)
            ],
            "A new certificate object is created per deployment and the profile is re-pointed, so "
            + "rollback is pointing the profile back at the previous object."),

        new("fortigate", "FortiGate", "Network", "rest",
            true, true, true, true, false, false, false,
            [ManagementUrl, new("vdom", "VDOM", "Virtual domain the certificate belongs to.", Default: "root"), AllowInsecureTls],
            [
                new("certObjectName", "Certificate object name", Required: true),
                new("bindingRef", "Binding field", "system/global field to re-point, e.g. admin-server-cert.")
            ]),

        new("paloalto", "Palo Alto PAN-OS", "Network", "rest",
            true, true, true, true, true,  false, RequiresCommit: true,
            [ManagementUrl, new("vsys", "Virtual system", Default: "vsys1"), AllowInsecureTls],
            [
                new("certObjectName", "Certificate object name", Required: true),
                new("bindingRef", "SSL/TLS service profile", "Profile updated to use the new certificate.")
            ],
            "PAN-OS keeps a candidate configuration; nothing takes effect until the commit step."),

        new("citrix-adc", "Citrix ADC", "Network", "rest",
            true, true, true, true, true, false, RequiresCommit: true,
            [ManagementUrl, new("partition", "Admin partition", Default: "default"), AllowInsecureTls],
            [
                new("certObjectName", "Certkey name", Required: true),
                new("bindingRef", "Virtual server", "vserver the certkey is bound to.")
            ],
            "The running configuration must be saved, or the binding is lost on reboot."),

        new("cisco-ise", "Cisco ISE", "Network", "rest",
            true, true, false, true, false, false, false,
            [ManagementUrl, AllowInsecureTls],
            [
                new("certObjectName", "Certificate name", Required: true),
                new("bindingRef", "Usage", "Comma-separated roles, e.g. eap,admin,portal.")
            ],
            "ISE replaces the system certificate in place and restarts the affected services, so "
            + "there is no previous object to roll back to.")
    ];

    public static AdapterDescriptor? Find(string type) =>
        All.FirstOrDefault(a => string.Equals(a.Type, type, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Whether an adapter can roll back at all (§9.3). Asked before a rollback is offered, so the
    /// operator is not given a button that would only produce an error.
    /// </summary>
    public static bool SupportsRollback(string type) => Find(type)?.SupportsRollback ?? true;

    /// <summary>Adapters that cannot deploy without the private key in RemoteSSL's hands.</summary>
    public static bool RequiresPrivateKey(string type) => Find(type)?.RequiresPrivateKey ?? true;
}
