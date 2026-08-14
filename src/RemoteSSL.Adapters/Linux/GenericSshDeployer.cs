using System.Text;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Linux;

/// <summary>
/// The escape hatch of design doc §14.2: a device or application with no purpose-built adapter,
/// driven by command templates the operator configured. Every command comes from this payload —
/// which comes from the target's own configuration — and never from a certificate field, a target
/// name, or anything else an outsider could influence.
/// </summary>
public sealed class GenericSshPayload
{
    public SshTargetConfig Connection { get; set; } = new("localhost");
    public Guid? CredentialRefId { get; set; }

    public string CertPath { get; set; } = string.Empty;
    public string? KeyPath { get; set; }
    public string? ChainPath { get; set; }

    /// <summary>Runs after the files are staged; typically an import or a vendor CLI call.</summary>
    public string? InstallCmd { get; set; }
    /// <summary>Config test. A non-zero exit rolls the deployment back before anything is reloaded.</summary>
    public string? ValidateCmd { get; set; }
    public string? ReloadCmd { get; set; }
    /// <summary>Must exit non-zero when the certificate did not actually take effect.</summary>
    public string? VerifyCmd { get; set; }
    /// <summary>Runs with {backupPath} when a later step fails.</summary>
    public string? RollbackCmd { get; set; }

    public string? Owner { get; set; }
    public string CertPem { get; set; } = string.Empty;
    public string? KeyPem { get; set; }
    public string? ChainPem { get; set; }
    public string? ExpectedSha256Thumbprint { get; set; }
}

/// <summary>
/// Runs the generic template pipeline (§14.2) through the same transactional shape as every other
/// adapter: pre-check, backup, upload, install, validate, reload, verify — and a rollback that
/// restores what was there before when any of it fails.
/// </summary>
public static class GenericSshDeployer
{
    /// <summary>
    /// Placeholders a template may use. Anything else is left alone, so a stray brace in a command
    /// does not silently become a substitution.
    /// </summary>
    public static string Render(string template, IReadOnlyDictionary<string, string> values)
    {
        var result = new StringBuilder(template);
        foreach (var (key, value) in values)
            result.Replace("{" + key + "}", value);
        return result.ToString();
    }

    public static DeployOutcome Deploy(GenericSshPayload p, SshCredentials creds)
    {
        var steps = new List<StepOutcome>();
        using var ssh = new SshConnection(p.Connection, creds);

        try
        {
            ssh.Connect();
            steps.Add(new("PreCheck", true, $"connected to {p.Connection.Host}"));
        }
        catch (Exception ex)
        {
            steps.Add(new("PreCheck", false, $"ssh connect failed: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
        var backupPath = $"{p.CertPath}.{stamp}.bak";
        var hadPrevious = ssh.FileExists(p.CertPath);

        var tokens = new Dictionary<string, string>
        {
            ["certPath"] = p.CertPath,
            ["keyPath"] = p.KeyPath ?? "",
            ["chainPath"] = p.ChainPath ?? "",
            ["backupPath"] = backupPath,
            ["thumbprint"] = p.ExpectedSha256Thumbprint ?? "",
            ["host"] = p.Connection.Host
        };

        // BACKUP — what rollback restores.
        if (hadPrevious)
        {
            var backup = Run(ssh, p, $"cp -p {Shell.Quote(p.CertPath)} {Shell.Quote(backupPath)}");
            if (!backup.Ok)
            {
                steps.Add(new("Backup", false, $"could not back up the existing file: {Trunc(backup.Stderr)}"));
                return new DeployOutcome(false, false, steps);
            }
            if (p.KeyPath is not null && ssh.FileExists(p.KeyPath))
                Run(ssh, p, $"cp -p {Shell.Quote(p.KeyPath)} {Shell.Quote(p.KeyPath + "." + stamp + ".bak")}");
        }
        steps.Add(new("Backup", true, hadPrevious ? $"previous file copied to {backupPath}" : "nothing to back up"));

        // UPLOAD
        try
        {
            ssh.UploadFile(Encoding.UTF8.GetBytes(p.CertPem), p.CertPath);
            if (p.KeyPath is not null && p.KeyPem is not null)
            {
                ssh.UploadFile(Encoding.UTF8.GetBytes(p.KeyPem), p.KeyPath);
                Run(ssh, p, $"chmod 600 {Shell.Quote(p.KeyPath)}");
            }
            if (p.ChainPath is not null && p.ChainPem is not null)
                ssh.UploadFile(Encoding.UTF8.GetBytes(p.ChainPem), p.ChainPath);
            if (p.Owner is not null)
                Run(ssh, p, $"chown {Shell.Quote(p.Owner)} {Shell.Quote(p.CertPath)}");
            steps.Add(new("PrepareUpload", true, "certificate material written"));
        }
        catch (Exception ex)
        {
            steps.Add(new("PrepareUpload", false, $"upload failed: {ex.Message}"));
            return Rollback(ssh, p, steps, tokens, hadPrevious ? backupPath : null);
        }

        // INSTALL / VALIDATE / RELOAD / VERIFY — each optional, each able to roll the change back.
        foreach (var (name, template) in new[]
                 {
                     ("Install", p.InstallCmd),
                     ("Validate", p.ValidateCmd),
                     ("Reload", p.ReloadCmd),
                     ("LocalVerify", p.VerifyCmd)
                 })
        {
            if (string.IsNullOrWhiteSpace(template)) continue;
            var result = Run(ssh, p, Render(template, tokens));
            if (!result.Ok)
            {
                steps.Add(new(name, false, $"{name.ToLowerInvariant()} command failed: {Trunc(result.Stderr)}"));
                return Rollback(ssh, p, steps, tokens, hadPrevious ? backupPath : null);
            }
            steps.Add(new(name, true, Trunc(result.Stdout).Trim() is { Length: > 0 } o ? o : "ok"));
        }

        steps.Add(new("Commit", true, hadPrevious
            ? $"previous file kept at {backupPath} for rollback"
            : "done"));
        return new DeployOutcome(true, false, steps);
    }

    private static DeployOutcome Rollback(SshConnection ssh, GenericSshPayload p, List<StepOutcome> steps,
        Dictionary<string, string> tokens, string? backupPath)
    {
        if (backupPath is null)
        {
            Run(ssh, p, $"rm -f {Shell.Quote(p.CertPath)}");
            steps.Add(new("Rollback", true, "the file this deployment added was removed"));
        }
        else
        {
            var restore = Run(ssh, p, $"cp -p {Shell.Quote(backupPath)} {Shell.Quote(p.CertPath)}");
            steps.Add(new("Rollback", restore.Ok, restore.Ok ? "previous file restored" : Trunc(restore.Stderr)));
            if (!restore.Ok) return new DeployOutcome(false, false, steps);
        }

        // The operator's own rollback command runs last: only it knows how to make the device
        // notice that the file went back.
        if (!string.IsNullOrWhiteSpace(p.RollbackCmd))
        {
            var custom = Run(ssh, p, Render(p.RollbackCmd, tokens));
            steps.Add(new("Rollback:command", custom.Ok, custom.Ok ? "ok" : Trunc(custom.Stderr)));
            if (!custom.Ok) return new DeployOutcome(false, false, steps);
        }
        else if (!string.IsNullOrWhiteSpace(p.ReloadCmd))
        {
            Run(ssh, p, Render(p.ReloadCmd, tokens));
        }

        return new DeployOutcome(false, true, steps);
    }

    private static ExecResult Run(SshConnection ssh, GenericSshPayload p, string command) =>
        ssh.Exec(p.Connection.UseSudo ? $"sudo -n sh -c {Shell.Quote(command)}" : command);

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}
