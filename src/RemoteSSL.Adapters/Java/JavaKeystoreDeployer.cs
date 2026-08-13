using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Java;

public sealed class JavaKeystorePayload
{
    public SshTargetConfig Connection { get; set; } = new("localhost");
    public Guid? CredentialRefId { get; set; }
    public string StorePath { get; set; } = string.Empty;
    public string StoreType { get; set; } = "JKS"; // JKS | PKCS12
    public string Alias { get; set; } = string.Empty;
    /// <summary>Keytool binary; defaults to keytool on PATH or $JAVA_HOME/bin/keytool.</summary>
    public string? KeytoolPath { get; set; }
    /// <summary>Store password — delivered at execution time, fed via environment, never argv.</summary>
    public string StorePassword { get; set; } = string.Empty;
    /// <summary>Trusted cert import (truststore) when key material is absent; else PrivateKeyEntry via PKCS12 bundle.</summary>
    public string CertPem { get; set; } = string.Empty;
    public byte[]? Pkcs12Bundle { get; set; }
    public string? Pkcs12Password { get; set; }
    public string? ReloadCmd { get; set; }
}

/// <summary>
/// Java keystore/truststore operations over SSH using keytool (design doc §12).
/// Passwords go through :env options (KEYTOOL_STOREPASS), keeping them out of argv
/// and shell history. Store file is backed up before mutation and restored on failure.
/// </summary>
public static class JavaKeystoreDeployer
{
    public static DeployOutcome Deploy(JavaKeystorePayload p, SshCredentials creds)
    {
        var steps = new List<StepOutcome>();
        var keytool = p.KeytoolPath ?? "keytool";
        var ts = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
        var backup = $"{p.StorePath}.rssl-bak-{ts}";

        using var ssh = new SshConnection(p.Connection, creds);
        try { ssh.Connect(); }
        catch (Exception ex)
        {
            steps.Add(new("PreCheck", false, $"ssh connect failed: {ex.Message}"));
            return new DeployOutcome(false, false, steps);
        }

        // PRE-CHECK: keytool present, store readable, alias conflict check
        var env = $"KEYTOOL_SP={Shell.Quote(p.StorePassword)}";
        if (!ssh.Exec($"command -v {Shell.Quote(keytool)} >/dev/null || test -x {Shell.Quote(keytool)}").Ok)
        {
            steps.Add(new("PreCheck", false, $"keytool not found: {keytool}"));
            return new DeployOutcome(false, false, steps);
        }
        var list = ssh.Exec($"{env} {keytool} -list -keystore {Shell.Quote(p.StorePath)} -storetype {p.StoreType} -storepass:env KEYTOOL_SP -alias {Shell.Quote(p.Alias)} 2>&1");
        var aliasExists = list.Ok;
        steps.Add(new("PreCheck", true, aliasExists ? $"alias '{p.Alias}' exists — will be replaced" : $"alias '{p.Alias}' is new"));

        // BACKUP
        if (ssh.FileExists(p.StorePath))
        {
            if (!ssh.Exec($"cp -p {Shell.Quote(p.StorePath)} {Shell.Quote(backup)}").Ok)
            {
                steps.Add(new("Backup", false, "store backup failed"));
                return new DeployOutcome(false, false, steps);
            }
        }
        steps.Add(new("Backup", true, backup));

        try
        {
            if (aliasExists)
                ssh.Exec($"{env} {keytool} -delete -alias {Shell.Quote(p.Alias)} -keystore {Shell.Quote(p.StorePath)} -storetype {p.StoreType} -storepass:env KEYTOOL_SP");

            ExecResult import;
            if (p.Pkcs12Bundle is { Length: > 0 })
            {
                // PrivateKeyEntry: importkeystore from staged PKCS12
                var tmp = $"/tmp/rssl-{ts}.p12";
                ssh.UploadFile(p.Pkcs12Bundle, tmp);
                ssh.Exec($"chmod 0600 {Shell.Quote(tmp)}");
                var env2 = $"{env} KEYTOOL_SRCP={Shell.Quote(p.Pkcs12Password ?? "")}";
                import = ssh.Exec(
                    $"{env2} {keytool} -importkeystore -srckeystore {Shell.Quote(tmp)} -srcstoretype PKCS12 " +
                    $"-srcstorepass:env KEYTOOL_SRCP -destkeystore {Shell.Quote(p.StorePath)} -deststoretype {p.StoreType} " +
                    $"-deststorepass:env KEYTOOL_SP -srcalias {Shell.Quote(p.Alias)} -destalias {Shell.Quote(p.Alias)} -noprompt 2>&1");
                ssh.Exec($"rm -f {Shell.Quote(tmp)}");
            }
            else
            {
                // Trusted certificate import
                var tmp = $"/tmp/rssl-{ts}.pem";
                ssh.UploadFile(System.Text.Encoding.UTF8.GetBytes(p.CertPem), tmp);
                import = ssh.Exec(
                    $"{env} {keytool} -importcert -file {Shell.Quote(tmp)} -alias {Shell.Quote(p.Alias)} " +
                    $"-keystore {Shell.Quote(p.StorePath)} -storetype {p.StoreType} -storepass:env KEYTOOL_SP -noprompt 2>&1");
                ssh.Exec($"rm -f {Shell.Quote(tmp)}");
            }

            if (!import.Ok)
            {
                steps.Add(new("Install", false, Trunc(import.Stdout + import.Stderr)));
                return Rollback(ssh, steps, p, backup);
            }
            steps.Add(new("Install", true, $"alias '{p.Alias}' imported"));

            // VALIDATE: store integrity + alias present
            var verify = ssh.Exec($"{env} {keytool} -list -keystore {Shell.Quote(p.StorePath)} -storetype {p.StoreType} -storepass:env KEYTOOL_SP -alias {Shell.Quote(p.Alias)} 2>&1");
            if (!verify.Ok)
            {
                steps.Add(new("ConfigValidate", false, "alias not found after import"));
                return Rollback(ssh, steps, p, backup);
            }
            steps.Add(new("ConfigValidate", true, "store integrity ok"));

            if (p.ReloadCmd is not null)
            {
                var r = ssh.Exec(p.ReloadCmd, TimeSpan.FromMinutes(3));
                steps.Add(new("Reload", r.Ok, r.Ok ? p.ReloadCmd : Trunc(r.Stderr)));
                if (!r.Ok) return Rollback(ssh, steps, p, backup);
            }

            steps.Add(new("Commit", true, $"backup retained: {backup}"));
            return new DeployOutcome(true, false, steps);
        }
        catch (Exception ex)
        {
            steps.Add(new("Error", false, Trunc(ex.Message)));
            return Rollback(ssh, steps, p, backup);
        }
    }

    private static DeployOutcome Rollback(SshConnection ssh, List<StepOutcome> steps, JavaKeystorePayload p, string backup)
    {
        var ok = !ssh.FileExists(backup) || ssh.Exec($"cp -p {Shell.Quote(backup)} {Shell.Quote(p.StorePath)}").Ok;
        steps.Add(new("Rollback", ok, ok ? "store restored from backup" : "restore failed — manual intervention required"));
        return new DeployOutcome(false, ok, steps);
    }

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}
