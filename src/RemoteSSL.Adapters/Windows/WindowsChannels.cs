using System.Diagnostics;
using System.Text;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Windows;

/// <summary>
/// Management channel abstraction for Windows targets (design doc §11.1): WinRM /
/// PowerShell Remoting is the primary channel (executed natively from a Windows
/// runner); SSH (Windows OpenSSH) is the alternative channel.
/// </summary>
public interface IWindowsChannel : IDisposable
{
    /// <summary>Runs a PowerShell script on the target and returns exit code + output.</summary>
    ExecResult RunPs(string script, TimeSpan? timeout = null);

    /// <summary>Copies a file to the target.</summary>
    void PutFile(byte[] content, string remotePath);
}

/// <summary>SSH channel: PowerShell via Windows OpenSSH, files via SFTP.</summary>
public sealed class SshWindowsChannel(SshTargetConfig target, SshCredentials creds) : IWindowsChannel
{
    private readonly SshConnection _ssh = Connect(target, creds);

    private static SshConnection Connect(SshTargetConfig target, SshCredentials creds)
    {
        var ssh = new SshConnection(target, creds);
        ssh.Connect();
        return ssh;
    }

    public ExecResult RunPs(string script, TimeSpan? timeout = null)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return _ssh.Exec($"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}",
            timeout ?? TimeSpan.FromMinutes(3));
    }

    public void PutFile(byte[] content, string remotePath) => _ssh.UploadFile(content, remotePath);

    public void Dispose() => _ssh.Dispose();
}

/// <summary>
/// WinRM channel: native PowerShell Remoting executed from a Windows runner.
/// The credential password reaches PowerShell through an environment variable —
/// never the command line. Requires the runner host to be Windows.
/// </summary>
public sealed class WinRmWindowsChannel : IWindowsChannel
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _useSsl;
    private readonly string _username;
    private readonly string _password;

    public WinRmWindowsChannel(string host, int port, bool useSsl, string username, string password)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "WinRM channel requires a Windows runner (PowerShell Remoting); deploy a runner in the Windows segment or use the SSH channel.");
        _host = host;
        _port = port == 0 ? (useSsl ? 5986 : 5985) : port;
        _useSsl = useSsl;
        _username = username;
        _password = password;
    }

    public ExecResult RunPs(string script, TimeSpan? timeout = null)
    {
        var remote = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var wrapper = $$"""
$ErrorActionPreference = 'Stop'
try {
  $pw = ConvertTo-SecureString $env:RSSL_WINRM_PW -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($env:RSSL_WINRM_USER, $pw)
  $so = New-PSSessionOption -SkipCACheck -SkipCNCheck
  $s = New-PSSession -ComputerName '{{_host}}' -Port {{_port}} {{(_useSsl ? "-UseSSL" : "")}} -Credential $cred -SessionOption $so
  try {
    $sb = [scriptblock]::Create([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{{remote}}')))
    $out = Invoke-Command -Session $s -ScriptBlock $sb
    $out | Out-String | Write-Output
  } finally { Remove-PSSession $s }
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
""";
        return RunLocal(wrapper, timeout ?? TimeSpan.FromMinutes(3));
    }

    public void PutFile(byte[] content, string remotePath)
    {
        var local = Path.Combine(Path.GetTempPath(), $"rssl-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(local, content);
        try
        {
            var wrapper = $$"""
$ErrorActionPreference = 'Stop'
$pw = ConvertTo-SecureString $env:RSSL_WINRM_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:RSSL_WINRM_USER, $pw)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck
$s = New-PSSession -ComputerName '{{_host}}' -Port {{_port}} {{(_useSsl ? "-UseSSL" : "")}} -Credential $cred -SessionOption $so
try { Copy-Item -Path '{{local}}' -Destination '{{remotePath}}' -ToSession $s -Force }
finally { Remove-PSSession $s }
""";
            var result = RunLocal(wrapper, TimeSpan.FromMinutes(3));
            if (!result.Ok) throw new IOException($"WinRM file copy failed: {result.Stderr}");
        }
        finally
        {
            File.Delete(local);
        }
    }

    private ExecResult RunLocal(string script, TimeSpan timeout)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        psi.Environment["RSSL_WINRM_USER"] = _username;
        psi.Environment["RSSL_WINRM_PW"] = _password;

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        if (!process.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            return new ExecResult(-1, stdout, "WinRM command timed out");
        }
        return new ExecResult(process.ExitCode, stdout, stderr);
    }

    public void Dispose() { }
}
