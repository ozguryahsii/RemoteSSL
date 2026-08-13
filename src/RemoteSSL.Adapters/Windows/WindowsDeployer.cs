using System.Text;
using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Windows;

public sealed class WindowsDeployPayload
{
    public SshTargetConfig Connection { get; set; } = new("localhost");
    public Guid? CredentialRefId { get; set; }
    /// <summary>"LocalMachine\\My" style store path.</summary>
    public string StorePath { get; set; } = "LocalMachine\\My";
    public byte[] PfxBytes { get; set; } = [];
    public string PfxPassword { get; set; } = string.Empty;
    /// <summary>IIS site name; null = store import only, no binding update.</summary>
    public string? IisSiteName { get; set; }
    public string? IisHostHeader { get; set; }
    public int IisPort { get; set; } = 443;
    public string? ExpectedSha1Thumbprint { get; set; }
}

/// <summary>
/// Windows certificate store + IIS binding pipeline (design doc §11) executed over
/// SSH (Windows OpenSSH) with PowerShell. The PFX password travels via stdin-fed
/// SecureString file, never on a command line. Rollback restores the previous
/// binding thumbprint recorded during pre-check.
/// </summary>
public static class WindowsDeployer
{
    public static DeployOutcome Deploy(WindowsDeployPayload p, SshCredentials creds)
    {
        var steps = new List<StepOutcome>();
        using var ssh = new SshConnection(p.Connection, creds);
        try { ssh.Connect(); }
        catch (Exception ex)
        {
            steps.Add(new("PreCheck", false, $"ssh connect failed: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        var ts = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
        var tempPfx = $"C:/Windows/Temp/rssl-{ts}.pfx";
        var tempPwd = $"C:/Windows/Temp/rssl-{ts}.pwd";
        string? previousThumbprint = null;

        try
        {
            // PRE-CHECK: PowerShell available; record current binding thumbprint for rollback
            var check = Ps(ssh, "$PSVersionTable.PSVersion.Major");
            if (!check.Ok)
            {
                steps.Add(new("PreCheck", false, "PowerShell not reachable over SSH"));
                return new DeployOutcome(false, false, steps);
            }
            if (p.IisSiteName is not null)
            {
                var q = Ps(ssh,
                    $"Import-Module WebAdministration; (Get-ChildItem IIS:\\SslBindings | Where-Object {{$_.Port -eq {p.IisPort}}} | Select-Object -First 1).Thumbprint");
                previousThumbprint = q.Stdout.Trim();
            }
            steps.Add(new("PreCheck", true, $"powershell ok; previous binding {previousThumbprint ?? "none"}"));

            // UPLOAD PFX + password file (restrictive location)
            ssh.UploadFile(p.PfxBytes, tempPfx);
            ssh.UploadFile(Encoding.UTF8.GetBytes(p.PfxPassword), tempPwd);
            steps.Add(new("PrepareUpload", true, "pfx staged to temp"));

            // INSTALL into store
            var storeName = p.StorePath.Split('\\').Last();
            var location = p.StorePath.StartsWith("CurrentUser", StringComparison.OrdinalIgnoreCase) ? "CurrentUser" : "LocalMachine";
            var import = Ps(ssh,
                $"$pwd = ConvertTo-SecureString (Get-Content '{tempPwd}' -Raw) -AsPlainText -Force; " +
                $"$c = Import-PfxCertificate -FilePath '{tempPfx}' -CertStoreLocation Cert:\\{location}\\{storeName} -Password $pwd; " +
                "$c.Thumbprint");
            var newThumb = import.Stdout.Trim();
            if (!import.Ok || string.IsNullOrEmpty(newThumb))
            {
                steps.Add(new("Install", false, $"Import-PfxCertificate failed: {import.Stderr}"));
                return new DeployOutcome(false, false, steps);
            }
            if (p.ExpectedSha1Thumbprint is not null && !newThumb.Equals(p.ExpectedSha1Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                steps.Add(new("Install", false, $"imported thumbprint {newThumb} != expected"));
                return new DeployOutcome(false, false, steps);
            }
            steps.Add(new("Install", true, $"imported {newThumb} into {location}\\{storeName}"));

            // ACTIVATE: IIS https binding update
            if (p.IisSiteName is not null)
            {
                var bind = Ps(ssh,
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
                    return RollbackBinding(ssh, steps, p, previousThumbprint);
                }
                steps.Add(new("Activate", true, $"IIS site '{p.IisSiteName}' :{p.IisPort} bound to {newThumb}"));

                // VERIFY: read binding back
                var verify = Ps(ssh,
                    $"Import-Module WebAdministration; (Get-ChildItem IIS:\\SslBindings | Where-Object {{$_.Port -eq {p.IisPort}}} | Select-Object -First 1).Thumbprint");
                if (!verify.Stdout.Trim().Equals(newThumb, StringComparison.OrdinalIgnoreCase))
                {
                    steps.Add(new("LocalVerify", false, "binding readback mismatch"));
                    return RollbackBinding(ssh, steps, p, previousThumbprint);
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
            Ps(ssh, $"Remove-Item -Force -ErrorAction SilentlyContinue '{tempPfx}','{tempPwd}'");
        }
    }

    private static DeployOutcome RollbackBinding(SshConnection ssh, List<StepOutcome> steps,
        WindowsDeployPayload p, string? previousThumbprint)
    {
        if (previousThumbprint is null || p.IisSiteName is null)
        {
            steps.Add(new("Rollback", false, "no previous binding recorded"));
            return new DeployOutcome(false, false, steps);
        }
        var r = Ps(ssh,
            "Import-Module WebAdministration; " +
            $"$b = Get-WebBinding -Name '{p.IisSiteName}' -Protocol https -Port {p.IisPort}; " +
            $"$b.AddSslCertificate('{previousThumbprint}', 'My')");
        steps.Add(new("Rollback", r.Ok, r.Ok ? $"binding restored to {previousThumbprint}" : Trunc(r.Stderr)));
        return new DeployOutcome(false, r.Ok, steps);
    }

    private static ExecResult Ps(SshConnection ssh, string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return ssh.Exec($"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}", TimeSpan.FromMinutes(3));
    }

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}
