using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Oracle;

public sealed class OracleWalletPayload
{
    public SshTargetConfig Connection { get; set; } = new("localhost");
    public Guid? CredentialRefId { get; set; }
    public string WalletPath { get; set; } = string.Empty;
    public string? OrapkiPath { get; set; }
    public string WalletPassword { get; set; } = string.Empty;
    /// <summary>"trusted" (root/intermediate) or "user" (leaf for an existing wallet CSR).</summary>
    public string CertKind { get; set; } = "trusted";
    public string CertPem { get; set; } = string.Empty;
    public bool RefreshAutoLogin { get; set; } = true;
    public string? ReloadCmd { get; set; }
}

/// <summary>
/// Oracle wallet operations via orapki over SSH (design doc §13). ewallet.p12 and
/// cwallet.sso are backed up and rolled back together — restoring only one of them
/// would leave the wallet inconsistent. Wallet password is passed via orapki's
/// -pwd from an env var to keep it off the command line where supported.
/// </summary>
public static class OracleWalletDeployer
{
    public static DeployOutcome Deploy(OracleWalletPayload p, SshCredentials creds)
    {
        var steps = new List<StepOutcome>();
        var orapki = p.OrapkiPath ?? "orapki";
        var ts = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
        string[] walletFiles = ["ewallet.p12", "cwallet.sso"];

        using var ssh = new SshConnection(p.Connection, creds);
        try { ssh.Connect(); }
        catch (Exception ex)
        {
            steps.Add(new("PreCheck", false, $"ssh connect failed: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        if (!ssh.Exec($"command -v {Shell.Quote(orapki)} >/dev/null || test -x {Shell.Quote(orapki)}").Ok)
        {
            steps.Add(new("PreCheck", false, $"orapki not found: {orapki}"));
            return new DeployOutcome(false, false, steps);
        }
        if (!ssh.Exec($"test -f {Shell.Quote($"{p.WalletPath}/ewallet.p12")}").Ok)
        {
            steps.Add(new("PreCheck", false, $"no wallet at {p.WalletPath}"));
            return new DeployOutcome(false, false, steps);
        }
        steps.Add(new("PreCheck", true, "orapki + wallet present"));

        // BACKUP both wallet files together
        var backupDir = $"{p.WalletPath}/.rssl-bak-{ts}";
        ssh.Exec($"mkdir -p {Shell.Quote(backupDir)}");
        foreach (var f in walletFiles)
        {
            if (ssh.FileExists($"{p.WalletPath}/{f}") &&
                !ssh.Exec($"cp -p {Shell.Quote($"{p.WalletPath}/{f}")} {Shell.Quote(backupDir)}").Ok)
            {
                steps.Add(new("Backup", false, $"backup failed for {f}"));
                return new DeployOutcome(false, false, steps);
            }
        }
        steps.Add(new("Backup", true, backupDir));

        var env = $"RSSL_WP={Shell.Quote(p.WalletPassword)}";
        try
        {
            var tmp = $"/tmp/rssl-{ts}.pem";
            ssh.UploadFile(System.Text.Encoding.UTF8.GetBytes(p.CertPem), tmp);
            var kindFlag = p.CertKind == "user" ? "-user_cert" : "-trusted_cert";
            var import = ssh.Exec(
                $"{env} {orapki} wallet add -wallet {Shell.Quote(p.WalletPath)} {kindFlag} -cert {Shell.Quote(tmp)} -pwd \"$RSSL_WP\" 2>&1",
                TimeSpan.FromMinutes(2));
            ssh.Exec($"rm -f {Shell.Quote(tmp)}");
            if (!import.Ok)
            {
                steps.Add(new("Install", false, Trunc(import.Stdout + import.Stderr)));
                return Rollback(ssh, steps, p, backupDir, walletFiles);
            }
            steps.Add(new("Install", true, $"{p.CertKind} certificate added"));

            if (p.RefreshAutoLogin)
            {
                var sso = ssh.Exec($"{env} {orapki} wallet create -wallet {Shell.Quote(p.WalletPath)} -auto_login -pwd \"$RSSL_WP\" 2>&1");
                steps.Add(new("Activate", sso.Ok, sso.Ok ? "auto-login wallet refreshed" : Trunc(sso.Stdout + sso.Stderr)));
                if (!sso.Ok) return Rollback(ssh, steps, p, backupDir, walletFiles);
            }

            // VALIDATE: wallet parses
            var display = ssh.Exec($"{env} {orapki} wallet display -wallet {Shell.Quote(p.WalletPath)} -pwd \"$RSSL_WP\" 2>&1");
            if (!display.Ok)
            {
                steps.Add(new("ConfigValidate", false, "wallet display failed after change"));
                return Rollback(ssh, steps, p, backupDir, walletFiles);
            }
            steps.Add(new("ConfigValidate", true, "wallet parse ok"));

            if (p.ReloadCmd is not null)
            {
                var r = ssh.Exec(p.ReloadCmd, TimeSpan.FromMinutes(3));
                steps.Add(new("Reload", r.Ok, r.Ok ? p.ReloadCmd : Trunc(r.Stderr)));
                if (!r.Ok) return Rollback(ssh, steps, p, backupDir, walletFiles);
            }

            steps.Add(new("Commit", true, $"backup retained: {backupDir}"));
            return new DeployOutcome(true, false, steps);
        }
        catch (Exception ex)
        {
            steps.Add(new("Error", false, Trunc(ex.Message)));
            return Rollback(ssh, steps, p, backupDir, walletFiles);
        }
    }

    private static DeployOutcome Rollback(SshConnection ssh, List<StepOutcome> steps,
        OracleWalletPayload p, string backupDir, string[] walletFiles)
    {
        var ok = true;
        foreach (var f in walletFiles)
        {
            var bak = $"{backupDir}/{f}";
            if (ssh.FileExists(bak) && !ssh.Exec($"cp -p {Shell.Quote(bak)} {Shell.Quote($"{p.WalletPath}/{f}")}").Ok)
                ok = false;
        }
        steps.Add(new("Rollback", ok, ok ? "both wallet files restored together" : "restore failed — manual intervention required"));
        return new DeployOutcome(false, ok, steps);
    }

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}
