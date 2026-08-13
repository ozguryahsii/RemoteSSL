using System.Text;
using Renci.SshNet;

namespace RemoteSSL.Adapters.Ssh;

public sealed record SshCredentials(string Username, string? Password, string? PrivateKeyPem);

public sealed record SshTargetConfig(string Host, int Port = 22, bool UseSudo = false);

public sealed record ExecResult(int ExitCode, string Stdout, string Stderr)
{
    public bool Ok => ExitCode == 0;
}

/// <summary>
/// Thin SSH/SFTP wrapper for adapters. Commands are built from structured arguments
/// by callers (no raw user shell strings, design doc §30.2); secrets never enter the
/// command line.
/// </summary>
public sealed class SshConnection : IDisposable
{
    private readonly SshClient _ssh;
    private readonly SftpClient _sftp;
    private readonly bool _useSudo;

    public SshConnection(SshTargetConfig target, SshCredentials creds)
    {
        var auth = new List<AuthenticationMethod>();
        if (!string.IsNullOrEmpty(creds.PrivateKeyPem))
        {
            using var keyStream = new MemoryStream(Encoding.UTF8.GetBytes(creds.PrivateKeyPem));
            auth.Add(new PrivateKeyAuthenticationMethod(creds.Username, new PrivateKeyFile(keyStream)));
        }
        if (!string.IsNullOrEmpty(creds.Password))
            auth.Add(new PasswordAuthenticationMethod(creds.Username, creds.Password));
        if (auth.Count == 0) throw new ArgumentException("SSH credentials require a password or private key.");

        var info = new ConnectionInfo(target.Host, target.Port, creds.Username, auth.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        _ssh = new SshClient(info);
        _sftp = new SftpClient(info);
        _useSudo = target.UseSudo;
    }

    public void Connect()
    {
        _ssh.Connect();
        _sftp.Connect();
    }

    public ExecResult Exec(string command, TimeSpan? timeout = null)
    {
        var full = _useSudo ? $"sudo -n {command}" : command;
        using var cmd = _ssh.CreateCommand(full);
        cmd.CommandTimeout = timeout ?? TimeSpan.FromSeconds(60);
        var stdout = cmd.Execute();
        return new ExecResult(cmd.ExitStatus ?? -1, stdout, cmd.Error);
    }

    public void UploadFile(byte[] content, string remotePath)
    {
        using var ms = new MemoryStream(content);
        _sftp.UploadFile(ms, remotePath, canOverride: true);
    }

    public byte[] DownloadFile(string remotePath)
    {
        using var ms = new MemoryStream();
        _sftp.DownloadFile(remotePath, ms);
        return ms.ToArray();
    }

    public bool FileExists(string remotePath) => _sftp.Exists(remotePath);

    public void Dispose()
    {
        _ssh.Dispose();
        _sftp.Dispose();
    }
}

/// <summary>Shell-safe single-quoting for path/argument values.</summary>
public static class Shell
{
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";
}
