using System.Text;
using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Windows;

public sealed class WindowsDeployPayload
{
    public SshTargetConfig Connection { get; set; } = new("localhost");
    public Guid? CredentialRefId { get; set; }
    /// <summary>"winrm" (primary, design doc §11.1) or "ssh" (alternative). Default winrm.</summary>
    public string Method { get; set; } = "winrm";
    public bool WinRmUseSsl { get; set; }
    /// <summary>"LocalMachine\\My" style store path.</summary>
    public string StorePath { get; set; } = "LocalMachine\\My";
    public byte[] PfxBytes { get; set; } = [];
    public string PfxPassword { get; set; } = string.Empty;
    /// <summary>IIS site name; null = store import only, no binding update.</summary>
    public string? IisSiteName { get; set; }
    public string? IisHostHeader { get; set; }
    public int IisPort { get; set; } = 443;
    public string? ExpectedSha1Thumbprint { get; set; }

    /// <summary>
    /// Import the private key as non-exportable (design doc §11.4). Default on: once the key is in
    /// the store there is no legitimate reason for it to be copied out again.
    /// </summary>
    public bool NonExportablePrivateKey { get; set; } = true;

    /// <summary>
    /// Accounts that get read access to the private key — the app pool or service identity that
    /// has to use the certificate, e.g. "IIS AppPool\\Default Web Site" or "NT SERVICE\\W3SVC"
    /// (§11.4). Without this, a non-exportable key installed by an admin is unreadable by the
    /// service that needs it.
    /// </summary>
    public List<string> PrivateKeyReadAccounts { get; set; } = [];

    /// <summary>
    /// System services to point at the same certificate after it is in the store (§11.4):
    /// "rdp" for Remote Desktop, "winrm" for the WinRM HTTPS listener.
    /// </summary>
    public List<string> BindingTargets { get; set; } = [];

    /// <summary>
    /// Centralized Certificate Store share (§11.4). When set, the PFX is placed on this UNC path
    /// instead of being imported into the machine store, and IIS serves it by host name.
    /// </summary>
    public string? CcsPath { get; set; }
    /// <summary>CCS file name without extension; defaults to the certificate's common name.</summary>
    public string? CcsFileName { get; set; }
    /// <summary>Turn the central certificate provider on for the site if it is off.</summary>
    public bool EnableCcs { get; set; }
}

/// <summary>
/// Windows certificate store + IIS binding pipeline (design doc §11). The management
/// channel is WinRM/PowerShell Remoting by default (§11.1), with SSH as the
/// alternative. The PFX password travels via a SecureString built from a file/env
/// value, never on a command line. Rollback restores the previous binding thumbprint
/// recorded during pre-check.
/// </summary>
public static class WindowsDeployer
{
    public static DeployOutcome Deploy(WindowsDeployPayload p, SshCredentials creds)
    {
        var steps = new List<StepOutcome>();
        IWindowsChannel channel;
        try
        {
            channel = p.Method.Equals("ssh", StringComparison.OrdinalIgnoreCase)
                ? new SshWindowsChannel(p.Connection, creds)
                : new WinRmWindowsChannel(p.Connection.Host, p.Connection.Port == 22 ? 0 : p.Connection.Port,
                    p.WinRmUseSsl, creds.Username, creds.Password ?? "");
        }
        catch (Exception ex)
        {
            steps.Add(new("PreCheck", false, $"{p.Method} channel init failed: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        using (channel)
        {
            // CCS is a different shape of deployment: the certificate is never imported into this
            // machine's store, it is placed on a share that IIS reads by host name (§11.4).
            if (p.CcsPath is not null) return DeployToCcs(channel, p, steps);

            var ts = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
            var tempPfx = $"C:/Windows/Temp/rssl-{ts}.pfx";
            var tempPwd = $"C:/Windows/Temp/rssl-{ts}.pwd";
            string? previousThumbprint = null;

            try
            {
                // PRE-CHECK: PowerShell reachable; record current binding thumbprint for rollback
                var check = channel.RunPs("$PSVersionTable.PSVersion.Major");
                if (!check.Ok)
                {
                    steps.Add(new("PreCheck", false, $"PowerShell not reachable via {p.Method}: {check.Stderr}"));
                    return new DeployOutcome(false, false, steps);
                }
                if (p.IisSiteName is not null)
                {
                    var q = channel.RunPs(
                        $"Import-Module WebAdministration; (Get-ChildItem IIS:\\SslBindings | Where-Object {{$_.Port -eq {p.IisPort}}} | Select-Object -First 1).Thumbprint");
                    previousThumbprint = q.Stdout.Trim();
                }
                steps.Add(new("PreCheck", true, $"{p.Method} ok; previous binding {previousThumbprint ?? "none"}"));

                // PREPARE/UPLOAD PFX + password
                channel.PutFile(p.PfxBytes, tempPfx);
                channel.PutFile(Encoding.UTF8.GetBytes(p.PfxPassword), tempPwd);
                steps.Add(new("PrepareUpload", true, "pfx staged to temp"));

                // INSTALL into store
                var storeName = p.StorePath.Split('\\').Last();
                var location = p.StorePath.StartsWith("CurrentUser", StringComparison.OrdinalIgnoreCase) ? "CurrentUser" : "LocalMachine";
                // -Exportable is opt-in; leaving it off makes the key non-exportable (§11.4).
                var import = channel.RunPs(
                    $"$pwd = ConvertTo-SecureString (Get-Content '{tempPwd}' -Raw) -AsPlainText -Force; " +
                    $"$c = Import-PfxCertificate -FilePath '{tempPfx}' -CertStoreLocation Cert:\\{location}\\{storeName} -Password $pwd" +
                    (p.NonExportablePrivateKey ? "" : " -Exportable") + "; " +
                    "$c.Thumbprint");
                var newThumb = import.Stdout.Trim().Split('\n').LastOrDefault()?.Trim() ?? "";
                if (!import.Ok || string.IsNullOrEmpty(newThumb))
                {
                    steps.Add(new("Install", false, $"Import-PfxCertificate failed: {Trunc(import.Stderr)}"));
                    return new DeployOutcome(false, false, steps);
                }
                if (p.ExpectedSha1Thumbprint is not null && !newThumb.Equals(p.ExpectedSha1Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    steps.Add(new("Install", false, $"imported thumbprint {newThumb} != expected"));
                    return new DeployOutcome(false, false, steps);
                }
                steps.Add(new("Install", true, $"imported {newThumb} into {location}\\{storeName}"
                    + (p.NonExportablePrivateKey ? "; private key non-exportable" : "; private key exportable")));

                // PRIVATE KEY ACL: grant the service identity read access (§11.4)
                if (p.PrivateKeyReadAccounts.Count > 0)
                {
                    var acl = channel.RunPs(GrantPrivateKeyAccessScript(location, storeName, newThumb, p.PrivateKeyReadAccounts));
                    if (!acl.Ok)
                    {
                        steps.Add(new("PrivateKeyAcl", false, $"granting private key access failed: {Trunc(acl.Stderr)}"));
                        return new DeployOutcome(false, false, steps);
                    }
                    steps.Add(new("PrivateKeyAcl", true,
                        $"read access granted to {string.Join(", ", p.PrivateKeyReadAccounts)}"));
                }

                // ACTIVATE (system services): RDP and the WinRM HTTPS listener share the machine
                // store, so pointing them at the new thumbprint is all that is needed (§11.4).
                foreach (var service in p.BindingTargets)
                {
                    var script = ServiceBindingScript(service, newThumb);
                    if (script is null)
                    {
                        steps.Add(new("Activate", false, $"unknown system binding target '{service}'"));
                        return new DeployOutcome(false, false, steps);
                    }
                    var bound = channel.RunPs(script);
                    if (!bound.Ok)
                    {
                        steps.Add(new($"Activate:{service}", false, $"binding failed: {Trunc(bound.Stderr)}"));
                        return new DeployOutcome(false, false, steps);
                    }
                    steps.Add(new($"Activate:{service}", true, $"{service} now serves {newThumb}"));
                }

                // ACTIVATE: IIS https binding update
                if (p.IisSiteName is not null)
                {
                    var bind = channel.RunPs(
                        "Import-Module WebAdministration; " +
                        $"$b = Get-WebBinding -Name '{p.IisSiteName}' -Protocol https -Port {p.IisPort}" +
                        (p.IisHostHeader is not null ? $" -HostHeader '{p.IisHostHeader}'" : "") + "; " +
                        $"if (-not $b) {{ New-WebBinding -Name '{p.IisSiteName}' -Protocol https -Port {p.IisPort}" +
                        (p.IisHostHeader is not null ? $" -HostHeader '{p.IisHostHeader}' -SslFlags 1" : "") + "; " +
                        $"$b = Get-WebBinding -Name '{p.IisSiteName}' -Protocol https -Port {p.IisPort} }}; " +
                        $"$b.AddSslCertificate('{newThumb}', 'My')");
                    if (!bind.Ok)
                    {
                        steps.Add(new("Activate", false, $"IIS binding update failed: {Trunc(bind.Stderr)}"));
                        return RollbackBinding(channel, steps, p, previousThumbprint);
                    }
                    steps.Add(new("Activate", true, $"IIS site '{p.IisSiteName}' :{p.IisPort} bound to {newThumb}"));

                    // LOCAL VERIFY: read binding back
                    var verify = channel.RunPs(
                        $"Import-Module WebAdministration; (Get-ChildItem IIS:\\SslBindings | Where-Object {{$_.Port -eq {p.IisPort}}} | Select-Object -First 1).Thumbprint");
                    if (!verify.Stdout.Trim().Contains(newThumb, StringComparison.OrdinalIgnoreCase))
                    {
                        steps.Add(new("LocalVerify", false, "binding readback mismatch"));
                        return RollbackBinding(channel, steps, p, previousThumbprint);
                    }
                    steps.Add(new("LocalVerify", true, "binding verified"));
                }

                steps.Add(new("Commit", true, previousThumbprint is not null
                    ? $"previous cert {previousThumbprint} left in store for rollback"
                    : "done"));
                return new DeployOutcome(true, false, steps);
            }
            finally
            {
                channel.RunPs($"Remove-Item -Force -ErrorAction SilentlyContinue '{tempPfx}','{tempPwd}'");
            }
        }
    }

    private static DeployOutcome RollbackBinding(IWindowsChannel channel, List<StepOutcome> steps,
        WindowsDeployPayload p, string? previousThumbprint)
    {
        if (previousThumbprint is null || p.IisSiteName is null)
        {
            steps.Add(new("Rollback", false, "no previous binding recorded"));
            return new DeployOutcome(false, false, steps);
        }
        var r = channel.RunPs(
            "Import-Module WebAdministration; " +
            $"$b = Get-WebBinding -Name '{p.IisSiteName}' -Protocol https -Port {p.IisPort}; " +
            $"$b.AddSslCertificate('{previousThumbprint}', 'My')");
        steps.Add(new("Rollback", r.Ok, r.Ok ? $"binding restored to {previousThumbprint}" : Trunc(r.Stderr)));
        return new DeployOutcome(false, r.Ok, steps);
    }

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];

    /// <summary>
    /// Points a Windows system service at a certificate already in the machine store (§11.4).
    /// Returns null for an unrecognised target rather than running something unintended.
    /// </summary>
    public static string? ServiceBindingScript(string service, string thumbprint) =>
        service.ToLowerInvariant() switch
        {
            // Terminal Services keeps the thumbprint in WMI, not in an HTTP binding.
            "rdp" => "$ts = Get-WmiObject -Class Win32_TSGeneralSetting "
                     + "-Namespace root\\CIMV2\\TerminalServices -Filter \"TerminalName='RDP-tcp'\"; "
                     + $"$ts.SSLCertificateSHA1Hash = '{thumbprint}'; $ts.Put()",
            // The WinRM HTTPS listener is recreated rather than edited: changing the certificate
            // of an existing listener is not supported, and a missing listener must be created.
            "winrm" => "winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null; "
                       + "winrm create winrm/config/Listener?Address=*+Transport=HTTPS "
                       + $"'@{{Hostname=\"'+$env:COMPUTERNAME+'\";CertificateThumbprint=\"{thumbprint}\"}}'",
            _ => null
        };

    /// <summary>
    /// Centralized Certificate Store deployment (§11.4). CCS matches the requested host name to a
    /// PFX file on a share, so the work is placing the file under the right name — no machine
    /// store, no per-server binding. The previous file is kept alongside for rollback.
    /// </summary>
    private static DeployOutcome DeployToCcs(IWindowsChannel channel, WindowsDeployPayload p, List<StepOutcome> steps)
    {
        var name = (p.CcsFileName ?? p.IisHostHeader ?? "certificate").TrimEnd('.');
        var target = $"{p.CcsPath!.TrimEnd('\\', '/')}\\{name}.pfx";
        var backup = $"{target}.{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.bak";

        var check = channel.RunPs($"Test-Path '{p.CcsPath}'");
        if (!check.Ok || !check.Stdout.Trim().Equals("True", StringComparison.OrdinalIgnoreCase))
        {
            steps.Add(new("PreCheck", false, $"CCS share '{p.CcsPath}' is not reachable from the target"));
            return new DeployOutcome(false, false, steps);
        }
        steps.Add(new("PreCheck", true, $"CCS share reachable; target file {target}"));

        var existing = channel.RunPs($"if (Test-Path '{target}') {{ Copy-Item '{target}' '{backup}' -Force; 'backed-up' }} else {{ 'none' }}");
        var hadPrevious = existing.Stdout.Contains("backed-up");
        steps.Add(new("Backup", true, hadPrevious ? $"previous file copied to {backup}" : "no previous file"));

        try
        {
            channel.PutFile(p.PfxBytes, target.Replace('\\', '/'));
            steps.Add(new("Install", true, $"pfx written to {target}"));
        }
        catch (Exception ex)
        {
            steps.Add(new("Install", false, $"could not write to the CCS share: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        if (p.EnableCcs)
        {
            var enable = channel.RunPs(
                "Import-Module WebAdministration; "
                + $"Enable-WebCentralCertProvider -CertStoreLocation '{p.CcsPath}' "
                + "-UserName $env:USERNAME -Password (ConvertTo-SecureString ' ' -AsPlainText -Force) "
                + "-ErrorAction SilentlyContinue; "
                + "(Get-WebCentralCertProvider).Enabled");
            steps.Add(new("Activate", enable.Ok, enable.Ok
                ? "central certificate provider enabled"
                : $"could not enable CCS: {Trunc(enable.Stderr)}"));
            if (!enable.Ok) return RollbackCcs(channel, steps, target, hadPrevious ? backup : null);
        }

        var verify = channel.RunPs($"(Get-Item '{target}').Length");
        if (!verify.Ok || verify.Stdout.Trim() == "0")
        {
            steps.Add(new("LocalVerify", false, "the written file is missing or empty"));
            return RollbackCcs(channel, steps, target, hadPrevious ? backup : null);
        }
        steps.Add(new("LocalVerify", true, $"{verify.Stdout.Trim()} bytes on the share"));

        steps.Add(new("Commit", true, hadPrevious
            ? $"previous file kept at {backup} for rollback"
            : "done"));
        return new DeployOutcome(true, false, steps);
    }

    private static DeployOutcome RollbackCcs(IWindowsChannel channel, List<StepOutcome> steps,
        string target, string? backup)
    {
        if (backup is null)
        {
            channel.RunPs($"Remove-Item -Force -ErrorAction SilentlyContinue '{target}'");
            steps.Add(new("Rollback", true, "the file this deployment added was removed"));
            return new DeployOutcome(false, true, steps);
        }
        var restore = channel.RunPs($"Copy-Item '{backup}' '{target}' -Force");
        steps.Add(new("Rollback", restore.Ok, restore.Ok ? "previous file restored" : Trunc(restore.Stderr)));
        return new DeployOutcome(false, restore.Ok, steps);
    }

    /// <summary>
    /// Grants read access on the certificate's private key file to the given accounts (§11.4).
    /// CNG and legacy CSP keys live in different places, so both are tried; the script fails only
    /// when neither yields a key file, which means the certificate has no private key at all.
    /// </summary>
    public static string GrantPrivateKeyAccessScript(
        string location, string storeName, string thumbprint, IEnumerable<string> accounts)
    {
        var accountList = string.Join(",", accounts.Select(a => $"'{a.Replace("'", "''")}'"));
        return
            $"$cert = Get-Item Cert:\\{location}\\{storeName}\\{thumbprint}; " +
            "$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); " +
            "if (-not $key) { $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert) }; " +
            "if (-not $key) { throw 'certificate has no private key' }; " +
            "if ($key.Key -and $key.Key.UniqueName) { " +
            "  $path = Join-Path $env:ProgramData 'Microsoft\\Crypto\\Keys' | Join-Path -ChildPath $key.Key.UniqueName; " +
            "  if (-not (Test-Path $path)) { $path = Join-Path $env:ProgramData 'Microsoft\\Crypto\\RSA\\MachineKeys' | Join-Path -ChildPath $key.Key.UniqueName } " +
            "} else { " +
            "  $path = Join-Path $env:ProgramData 'Microsoft\\Crypto\\RSA\\MachineKeys' | Join-Path -ChildPath $key.CspKeyContainerInfo.UniqueKeyContainerName " +
            "}; " +
            "if (-not (Test-Path $path)) { throw \"private key file not found: $path\" }; " +
            "$acl = Get-Acl $path; " +
            $"foreach ($account in @({accountList})) {{ " +
            "  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($account,'Read','Allow'); " +
            "  $acl.AddAccessRule($rule) " +
            "}; " +
            "Set-Acl -Path $path -AclObject $acl; " +
            "'granted'";
    }
}
