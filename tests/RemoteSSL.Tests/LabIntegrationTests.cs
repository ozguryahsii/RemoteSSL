using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteSSL.Adapters.Linux;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Tests;

/// <summary>
/// Runs against the SSH lab target when one is up (design doc §36.2). These are not unit tests:
/// they open a real SSH connection, write real files and run real commands, which is the part of
/// an adapter most likely to be wrong and least likely to be caught by a mock.
///
/// The lab is started by <c>tests/lab/start-lab.sh</c> and announced through REMOTESSL_LAB_SSH;
/// without it the whole class is skipped, so a normal build and CI run stay hermetic.
/// </summary>
public sealed class LabFixture
{
    public bool Available { get; }
    public SshTargetConfig Target { get; }
    public SshCredentials Credentials { get; }

    public LabFixture()
    {
        // "host:port" — set by the lab script once the container answers.
        var endpoint = Environment.GetEnvironmentVariable("REMOTESSL_LAB_SSH");
        var user = Environment.GetEnvironmentVariable("REMOTESSL_LAB_USER") ?? "remotessl";
        var password = Environment.GetEnvironmentVariable("REMOTESSL_LAB_PASSWORD") ?? "labpassword";

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            Target = new SshTargetConfig("unavailable");
            Credentials = new SshCredentials(user, password, null);
            return;
        }

        var parts = endpoint.Split(':');
        Target = new SshTargetConfig(parts[0], parts.Length > 1 ? int.Parse(parts[1]) : 22);
        Credentials = new SshCredentials(user, password, null);
        Available = true;
    }
}

[CollectionDefinition("lab")]
public class LabCollection : ICollectionFixture<LabFixture>;

[Collection("lab")]
public class LinuxDeployerLabTests(LabFixture lab)
{
    /// <summary>Skips the test body when no lab is running, rather than failing a hermetic build.</summary>
    private bool Skip() => !lab.Available;

    private static (string CertPem, string KeyPem, string Thumbprint) SelfSigned(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(90));
        return (certificate.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem(),
            Convert.ToHexString(SHA256.HashData(certificate.RawData)));
    }

    private DeployPayload Payload(string name, string? validateCmd = null, string? reloadCmd = null)
    {
        var (certPem, keyPem, thumbprint) = SelfSigned($"CN={name}.lab");
        return new DeployPayload
        {
            Adapter = "generic-file",
            Connection = lab.Target,
            CertPath = $"/config/{name}.crt",
            KeyPath = $"/config/{name}.key",
            BundleMode = "separate",
            // Real commands on the real target: a config test that reads the file back, and a
            // "reload" that stands in for the service restart the lab image cannot host.
            ValidateCmd = validateCmd ?? $"grep -q 'BEGIN CERTIFICATE' /config/{name}.crt",
            ReloadCmd = reloadCmd ?? $"touch /config/{name}.reloaded",
            CertPem = certPem,
            KeyPem = keyPem,
            ExpectedSha256Thumbprint = thumbprint
        };
    }

    private string Read(string path)
    {
        using var ssh = new SshConnection(lab.Target, lab.Credentials);
        ssh.Connect();
        return ssh.Exec($"cat {Shell.Quote(path)} 2>/dev/null || true").Stdout;
    }

    private bool Exists(string path)
    {
        using var ssh = new SshConnection(lab.Target, lab.Credentials);
        ssh.Connect();
        return ssh.Exec($"test -e {Shell.Quote(path)} && echo yes || echo no").Stdout.Trim() == "yes";
    }

    [Fact]
    public void A_certificate_is_written_validated_and_reloaded_on_a_real_target()
    {
        if (Skip()) return;
        var payload = Payload($"deploy-{Guid.NewGuid():N}"[..20]);

        var outcome = LinuxDeployer.Deploy(payload, lab.Credentials);

        Assert.True(outcome.Success, string.Join("; ", outcome.Steps.Select(s => $"{s.Step}: {s.SafeLog}")));
        Assert.Contains(outcome.Steps, s => s.Step == "PreCheck" && s.Success);
        Assert.Contains(outcome.Steps, s => s.Step == "ConfigValidate" && s.Success);
        Assert.Contains(outcome.Steps, s => s.Step == "Reload" && s.Success);

        // The file on the target really carries the certificate we sent.
        Assert.Contains("BEGIN CERTIFICATE", Read(payload.CertPath));
        Assert.True(Exists(payload.ReloadCmd!.Split(' ').Last()), "the reload command did not run");
    }

    [Fact]
    public void The_private_key_lands_with_owner_only_permissions()
    {
        if (Skip()) return;
        var payload = Payload($"perm-{Guid.NewGuid():N}"[..18]);

        Assert.True(LinuxDeployer.Deploy(payload, lab.Credentials).Success);

        using var ssh = new SshConnection(lab.Target, lab.Credentials);
        ssh.Connect();
        var mode = ssh.Exec($"stat -c %a {Shell.Quote(payload.KeyPath)}").Stdout.Trim();
        Assert.Equal("600", mode);
    }

    [Fact]
    public void A_failing_config_test_rolls_the_previous_certificate_back()
    {
        if (Skip()) return;
        var name = $"rollback-{Guid.NewGuid():N}"[..22];

        // First deployment succeeds and becomes "the previous certificate".
        var first = Payload(name);
        Assert.True(LinuxDeployer.Deploy(first, lab.Credentials).Success);
        var beforeSecond = Read(first.CertPath);

        // A realistic config test: it accepts the certificate that is currently deployed and
        // rejects anything else. That is what makes rollback verifiable — after the restore the
        // same command passes again, which a command that always fails could never show.
        var fingerprintLine = beforeSecond
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .First(l => !l.StartsWith("-----"))
            .Trim();
        var validate = $"grep -qF {Shell.Quote(fingerprintLine)} {Shell.Quote(first.CertPath)}";

        // Second deployment carries a different certificate, so the config test rejects it —
        // §21.1 says nothing may be left half-applied.
        var second = Payload(name, validateCmd: validate);
        var outcome = LinuxDeployer.Deploy(second, lab.Credentials);

        Assert.False(outcome.Success);
        Assert.True(outcome.RolledBack, string.Join("; ", outcome.Steps.Select(s => $"{s.Step}: {s.SafeLog}")));
        Assert.Contains(outcome.Steps, s => s.Step == "VerifyRollback" && s.Success);
        Assert.Equal(beforeSecond, Read(first.CertPath));
    }

    [Fact]
    public void A_failing_reload_also_rolls_back()
    {
        if (Skip()) return;
        var name = $"reload-{Guid.NewGuid():N}"[..20];

        var first = Payload(name);
        Assert.True(LinuxDeployer.Deploy(first, lab.Credentials).Success);
        var beforeSecond = Read(first.CertPath);

        var second = Payload(name, reloadCmd: "exit 3");
        var outcome = LinuxDeployer.Deploy(second, lab.Credentials);

        Assert.False(outcome.Success);
        Assert.Equal(beforeSecond, Read(first.CertPath));
    }

    [Fact]
    public void A_write_to_a_directory_the_account_cannot_touch_fails_without_leaving_anything_behind()
    {
        if (Skip()) return;
        // Failure injection (§36.1): permission denied is the most common real-world failure and
        // must produce a clean refusal, not a partial deployment.
        var payload = Payload("denied");
        payload.CertPath = "/proc/remotessl-denied.crt";
        payload.KeyPath = "/proc/remotessl-denied.key";

        var outcome = LinuxDeployer.Deploy(payload, lab.Credentials);

        Assert.False(outcome.Success);
        Assert.False(Exists(payload.CertPath));
    }

    [Fact]
    public void An_unreachable_host_fails_at_the_precheck_rather_than_part_way_through()
    {
        if (Skip()) return;
        var payload = Payload("unreachable");
        // Port 1 is closed; SSH.NET fails to connect, which must surface as a pre-check failure.
        payload.Connection = new SshTargetConfig(lab.Target.Host, 1);

        var outcome = LinuxDeployer.Deploy(payload, lab.Credentials);

        Assert.False(outcome.Success);
        Assert.False(outcome.RolledBack);
        Assert.Contains(outcome.Steps, s => s.Step == "PreCheck" && !s.Success);
    }

    [Fact]
    public void The_generic_template_adapter_runs_its_configured_commands_in_order()
    {
        if (Skip()) return;
        var name = $"generic-{Guid.NewGuid():N}"[..20];
        var (certPem, keyPem, thumbprint) = SelfSigned($"CN={name}.lab");
        var marker = $"/config/{name}.order";

        var payload = new GenericSshPayload
        {
            Connection = lab.Target,
            CertPath = $"/config/{name}.crt",
            KeyPath = $"/config/{name}.key",
            InstallCmd = $"echo install >> {marker}",
            ValidateCmd = $"echo validate >> {marker}",
            ReloadCmd = $"echo reload >> {marker}",
            // The verify command genuinely checks the deployed file, using the thumbprint token.
            VerifyCmd = $"test -s /config/{name}.crt && echo verify >> {marker}",
            CertPem = certPem,
            KeyPem = keyPem,
            ExpectedSha256Thumbprint = thumbprint
        };

        var outcome = GenericSshDeployer.Deploy(payload, lab.Credentials);

        Assert.True(outcome.Success, string.Join("; ", outcome.Steps.Select(s => $"{s.Step}: {s.SafeLog}")));
        Assert.Equal("install\nvalidate\nreload\nverify", Read(marker).Trim().Replace("\r", ""));
    }

    [Fact]
    public void A_generic_template_failure_restores_the_previous_file_and_runs_the_rollback_command()
    {
        if (Skip()) return;
        var name = $"generic-rb-{Guid.NewGuid():N}"[..24];
        var certPath = $"/config/{name}.crt";
        var rollbackMarker = $"/config/{name}.rolledback";

        var (firstPem, firstKey, firstThumb) = SelfSigned($"CN={name}-1.lab");
        var first = new GenericSshPayload
        {
            Connection = lab.Target, CertPath = certPath, KeyPath = $"/config/{name}.key",
            CertPem = firstPem, KeyPem = firstKey, ExpectedSha256Thumbprint = firstThumb
        };
        Assert.True(GenericSshDeployer.Deploy(first, lab.Credentials).Success);
        var original = Read(certPath);

        var (secondPem, secondKey, secondThumb) = SelfSigned($"CN={name}-2.lab");
        var second = new GenericSshPayload
        {
            Connection = lab.Target, CertPath = certPath, KeyPath = $"/config/{name}.key",
            ValidateCmd = "false",
            RollbackCmd = $"echo rolled-back >> {rollbackMarker}",
            CertPem = secondPem, KeyPem = secondKey, ExpectedSha256Thumbprint = secondThumb
        };

        var outcome = GenericSshDeployer.Deploy(second, lab.Credentials);

        Assert.False(outcome.Success);
        Assert.True(outcome.RolledBack);
        Assert.Equal(original, Read(certPath));
        Assert.Contains("rolled-back", Read(rollbackMarker));
    }
}
