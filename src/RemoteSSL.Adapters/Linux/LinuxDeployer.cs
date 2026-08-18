using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Linux;

/// <summary>Deploy payload contract between control plane and runner (JSON).</summary>
public sealed class DeployPayload
{
    public string Adapter { get; set; } = "generic-file";
    public SshTargetConfig Connection { get; set; } = new("localhost");
    public Guid? CredentialRefId { get; set; }
    public string CertPath { get; set; } = string.Empty;
    public string KeyPath { get; set; } = string.Empty;
    public string? ChainPath { get; set; }
    /// <summary>"separate" = cert+key files; "combined" = single PEM bundle at CertPath (HAProxy).</summary>
    public string BundleMode { get; set; } = "separate";
    public string? ValidateCmd { get; set; }
    public string? ReloadCmd { get; set; }
    public string? FileMode { get; set; }
    public string? Owner { get; set; }
    public string CertPem { get; set; } = string.Empty;
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyPem { get; set; }
    public string? ChainPem { get; set; }
    public string? ExpectedSha256Thumbprint { get; set; }
}

public sealed record StepOutcome(string Step, bool Success, string SafeLog);

public sealed record DeployOutcome(bool Success, bool RolledBack, IReadOnlyList<StepOutcome> Steps);

/// <summary>
/// Transactional Linux deployment pipeline (design doc §10.2 / §21.1):
/// pre-check → backup → upload → atomic install → config validate → reload →
/// verify; any failure after backup triggers rollback + verify-rollback.
/// Safe logs carry paths/hashes/exit codes only — never file contents or secrets.
/// </summary>
public static class LinuxDeployer
{
    private static readonly Dictionary<string, (string? Validate, string? Reload, string Bundle)> AdapterDefaults = new()
    {
        ["nginx"] = ("nginx -t", "systemctl reload nginx", "separate"),
        ["apache"] = ("apachectl configtest", "systemctl reload apache2", "separate"),
        ["haproxy"] = (null, "systemctl reload haproxy", "combined"),
        ["generic-file"] = (null, null, "separate"),
    };

    public static DeployOutcome Deploy(DeployPayload p, SshCredentials creds)
    {
        var steps = new List<StepOutcome>();
        var defaults = AdapterDefaults.GetValueOrDefault(p.Adapter, (null, null, "separate"));
        var validateCmd = p.ValidateCmd ?? defaults.Item1;
        var reloadCmd = p.ReloadCmd ?? defaults.Item2;
        var bundleMode = p.BundleMode == "separate" && defaults.Item3 == "combined" ? "combined" : p.BundleMode;
        var ts = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");

        var managedFiles = new List<string> { p.CertPath };
        if (bundleMode == "separate")
        {
            // Refused rather than guessed: with no key path of its own, a run would fall back to
            // something like the store directory, and `mv` would drop the private key inside it
            // under the temporary name. Nothing is uploaded until there is a real path to write to.
            if (string.IsNullOrWhiteSpace(p.KeyPath) || p.KeyPath == p.CertPath)
                return new DeployOutcome(false, false,
                    [new("PreCheck", false,
                        "this binding has no private key path — set keyPath on it (the certificate "
                        + $"path is {p.CertPath})")]);
            managedFiles.Add(p.KeyPath);
            if (!string.IsNullOrEmpty(p.ChainPath)) managedFiles.Add(p.ChainPath!);
        }

        using var ssh = new SshConnection(p.Connection, creds);
        try
        {
            ssh.Connect();
        }
        catch (Exception ex)
        {
            steps.Add(new("PreCheck", false, $"ssh connect failed: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        bool backupTaken = false;
        try
        {
            // PRE-CHECK: parent dirs exist and are writable
            foreach (var f in managedFiles)
            {
                var slash = f.LastIndexOf('/');
                if (slash <= 0)
                {
                    steps.Add(new("PreCheck", false, $"not an absolute path: {f}"));
                    return new DeployOutcome(false, false, steps);
                }
                var dir = f[..slash];
                var r = ssh.Exec($"test -d {Shell.Quote(dir)} && test -w {Shell.Quote(dir)}");
                if (!r.Ok)
                {
                    steps.Add(new("PreCheck", false, $"directory missing or not writable: {dir}"));
                    return new DeployOutcome(false, false, steps);
                }
                // A path that is itself a directory would take the staged file *into* it under the
                // temporary name instead of replacing anything.
                if (ssh.Exec($"test -d {Shell.Quote(f)}").Ok)
                {
                    steps.Add(new("PreCheck", false, $"this is a directory, not a file to write: {f}"));
                    return new DeployOutcome(false, false, steps);
                }
            }
            steps.Add(new("PreCheck", true, $"dirs ok for {managedFiles.Count} file(s)"));

            // BACKUP existing files
            foreach (var f in managedFiles)
            {
                if (ssh.Exec($"test -f {Shell.Quote(f)}").Ok)
                {
                    var r = ssh.Exec($"cp -p {Shell.Quote(f)} {Shell.Quote($"{f}.rssl-bak-{ts}")}");
                    if (!r.Ok)
                    {
                        steps.Add(new("Backup", false, $"backup failed for {f}: {r.Stderr}"));
                        return new DeployOutcome(false, false, steps);
                    }
                    backupTaken = true;
                }
            }
            steps.Add(new("Backup", true, backupTaken ? $"timestamp {ts}" : "no existing files (fresh install)"));

            // UPLOAD to temp + atomic INSTALL
            var uploads = BuildFileSet(p, bundleMode);
            foreach (var (path, content) in uploads)
            {
                var tmp = $"{path}.rssl-tmp-{ts}";
                ssh.UploadFile(Encoding.UTF8.GetBytes(content), tmp);
                var mode = p.FileMode ?? (path == p.KeyPath || bundleMode == "combined" ? "0600" : "0644");
                var cmds = $"chmod {mode} {Shell.Quote(tmp)}"
                           + (p.Owner is not null ? $" && chown {Shell.Quote(p.Owner)} {Shell.Quote(tmp)}" : "")
                           + $" && mv -f {Shell.Quote(tmp)} {Shell.Quote(path)}";
                var r = ssh.Exec(cmds);
                if (!r.Ok)
                {
                    steps.Add(new("Install", false, $"install failed for {path}: {r.Stderr}"));
                    return Rollback(ssh, steps, managedFiles, ts, validateCmd, reloadCmd, backupTaken);
                }
            }
            steps.Add(new("Install", true, $"{uploads.Count} file(s) atomically replaced"));

            // CONFIG VALIDATE
            if (validateCmd is not null)
            {
                var r = ssh.Exec(validateCmd);
                if (!r.Ok)
                {
                    steps.Add(new("ConfigValidate", false, $"{validateCmd}: exit {r.ExitCode}: {Truncate(r.Stderr)}"));
                    return Rollback(ssh, steps, managedFiles, ts, validateCmd, reloadCmd, backupTaken);
                }
                steps.Add(new("ConfigValidate", true, validateCmd));
            }

            // RELOAD
            if (reloadCmd is not null)
            {
                var r = ssh.Exec(reloadCmd);
                if (!r.Ok)
                {
                    steps.Add(new("Reload", false, $"{reloadCmd}: exit {r.ExitCode}: {Truncate(r.Stderr)}"));
                    return Rollback(ssh, steps, managedFiles, ts, validateCmd, reloadCmd, backupTaken);
                }
                steps.Add(new("Reload", true, reloadCmd));
            }

            // LOCAL VERIFY: is the certificate we meant to install actually the one on disk?
            if (!string.IsNullOrEmpty(p.ExpectedSha256Thumbprint))
            {
                var verified = VerifyOnTarget(ssh, p, bundleMode, out var detail);
                if (!verified)
                {
                    steps.Add(new("LocalVerify", false, detail));
                    return Rollback(ssh, steps, managedFiles, ts, validateCmd, reloadCmd, backupTaken);
                }
                steps.Add(new("LocalVerify", true, detail));
            }

            steps.Add(new("Commit", true, $"backups retained with suffix .rssl-bak-{ts}"));
            return new DeployOutcome(true, false, steps);
        }
        catch (Exception ex)
        {
            steps.Add(new("Error", false, Truncate(ex.Message)));
            return backupTaken
                ? Rollback(ssh, steps, managedFiles, ts, validateCmd, reloadCmd, backupTaken)
                : new DeployOutcome(false, false, steps);
        }
    }

    public static DeployOutcome RollbackToBackup(DeployPayload p, SshCredentials creds, string backupTimestamp)
    {
        var steps = new List<StepOutcome>();
        var defaults = AdapterDefaults.GetValueOrDefault(p.Adapter, (null, null, "separate"));
        var managedFiles = new List<string> { p.CertPath };
        if (p.BundleMode == "separate")
        {
            managedFiles.Add(p.KeyPath);
            if (!string.IsNullOrEmpty(p.ChainPath)) managedFiles.Add(p.ChainPath!);
        }
        using var ssh = new SshConnection(p.Connection, creds);
        ssh.Connect();
        var outcome = Rollback(ssh, steps, managedFiles, backupTimestamp,
            p.ValidateCmd ?? defaults.Item1, p.ReloadCmd ?? defaults.Item2, backupTaken: true);
        return outcome with { Success = outcome.RolledBack };
    }

    /// <summary>
    /// Confirms the installed certificate is the one that was sent (§21.1 local verify).
    ///
    /// The direct check asks the target's own openssl for the fingerprint, which also proves the
    /// file parses as a certificate. Plenty of appliances and minimal images ship no openssl,
    /// though, and refusing to deploy to them would be a limitation of this code rather than a
    /// property of the target — so the fallback compares the file's own bytes against the PEM that
    /// was uploaded. That proves the right file is in place; whether the service is serving it is
    /// what the remote TLS verify of §21.1 answers, and that runs regardless.
    /// </summary>
    private static bool VerifyOnTarget(SshConnection ssh, DeployPayload p, string bundleMode, out string detail)
    {
        var fingerprint = ssh.Exec(
            $"openssl x509 -in {Shell.Quote(p.CertPath)} -noout -fingerprint -sha256 2>/dev/null");
        var actual = fingerprint.Stdout.Split('=').LastOrDefault()?.Trim().Replace(":", "") ?? "";

        if (fingerprint.Ok && actual.Length > 0)
        {
            if (actual.Equals(p.ExpectedSha256Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                detail = $"sha256 {actual}";
                return true;
            }
            detail = $"thumbprint mismatch: got {actual}";
            return false;
        }

        // No usable openssl on the target: compare the deployed bytes with what we sent.
        var deployed = ssh.Exec($"cat {Shell.Quote(p.CertPath)}");
        if (!deployed.Ok)
        {
            detail = "the certificate file could not be read back from the target";
            return false;
        }

        // Comparing against what BuildFileSet produced keeps one definition of "the file we sent";
        // re-deriving it here would be a second copy of the bundling rules, free to drift.
        var expected = BuildFileSet(p, bundleMode).First(f => f.Path == p.CertPath).Content;

        if (Normalize(deployed.Stdout) != Normalize(expected))
        {
            detail = "the file on the target does not match the certificate that was sent";
            return false;
        }

        detail = "content matches the certificate that was sent (no openssl on the target)";
        return true;
    }

    /// <summary>Ignores line-ending and trailing-whitespace differences the transfer may introduce.</summary>
    private static string Normalize(string pem) =>
        string.Join('\n', pem.Replace("\r\n", "\n").Split('\n').Select(l => l.TrimEnd())).Trim();

    private static DeployOutcome Rollback(SshConnection ssh, List<StepOutcome> steps,
        List<string> managedFiles, string ts, string? validateCmd, string? reloadCmd, bool backupTaken)
    {
        if (!backupTaken)
        {
            steps.Add(new("Rollback", false, "no backup available (fresh install failure); manual cleanup may be needed"));
            return new DeployOutcome(false, false, steps);
        }

        var ok = true;
        foreach (var f in managedFiles)
        {
            var bak = $"{f}.rssl-bak-{ts}";
            if (!ssh.FileExists(bak)) continue;
            var r = ssh.Exec($"cp -p {Shell.Quote(bak)} {Shell.Quote(f)}");
            if (!r.Ok) { ok = false; steps.Add(new("Rollback", false, $"restore failed for {f}: {r.Stderr}")); }
        }
        if (ok) steps.Add(new("Rollback", true, "previous files restored"));

        if (validateCmd is not null && !ssh.Exec(validateCmd).Ok) ok = false;
        if (reloadCmd is not null && !ssh.Exec(reloadCmd).Ok) ok = false;
        steps.Add(new("VerifyRollback", ok, ok ? "service reloaded with previous files" : "rollback verification failed — manual intervention required"));
        return new DeployOutcome(false, ok, steps);
    }

    private static List<(string Path, string Content)> BuildFileSet(DeployPayload p, string bundleMode)
    {
        var files = new List<(string, string)>();
        if (bundleMode == "combined")
        {
            var bundle = new StringBuilder(p.CertPem.Trim());
            if (!string.IsNullOrWhiteSpace(p.ChainPem)) bundle.Append('\n').Append(p.ChainPem!.Trim());
            if (!string.IsNullOrWhiteSpace(p.KeyPem)) bundle.Append('\n').Append(p.KeyPem!.Trim());
            files.Add((p.CertPath, bundle + "\n"));
        }
        else
        {
            var cert = p.CertPem.Trim();
            if (string.IsNullOrEmpty(p.ChainPath) && !string.IsNullOrWhiteSpace(p.ChainPem))
                cert = cert + "\n" + p.ChainPem!.Trim(); // fullchain in cert file (nginx convention)
            files.Add((p.CertPath, cert + "\n"));
            if (!string.IsNullOrWhiteSpace(p.KeyPem)) files.Add((p.KeyPath, p.KeyPem!.Trim() + "\n"));
            if (!string.IsNullOrEmpty(p.ChainPath) && !string.IsNullOrWhiteSpace(p.ChainPem))
                files.Add((p.ChainPath!, p.ChainPem!.Trim() + "\n"));
        }
        return files;
    }

    private static string Truncate(string s) => s.Length <= 500 ? s : s[..500];
}
