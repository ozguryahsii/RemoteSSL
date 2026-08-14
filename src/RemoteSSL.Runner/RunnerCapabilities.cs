using System.Diagnostics;

namespace RemoteSSL.Runner;

/// <summary>
/// What this runner can actually do, per design doc §8.2: "Runner heartbeat capability listesi
/// yayınlamalıdır: ssh, winrm, powershell, openssl, keytool, orapki, vendor adapters."
///
/// The tool half is <em>detected</em>, not declared. A hard-coded list would let a runner with no
/// JDK advertise <c>keytool</c>, claim a Java keystore job and only discover the truth on the
/// customer's server, half-way through a deployment — exactly where a failure is most expensive.
/// Detection happens once at startup: these are installed packages, not things that change while
/// the process runs, and probing them on every heartbeat would spawn processes for nothing.
/// </summary>
public static class RunnerCapabilities
{
    /// <summary>Transports and tools this runner really has, plus the adapters it ships.</summary>
    public static IReadOnlyList<string> Detect() => Cached.Value;

    private static readonly Lazy<IReadOnlyList<string>> Cached = new(Build);

    /// <summary>Adapters compiled into this runner binary (§8.2 "vendor adapters").</summary>
    public static readonly IReadOnlyList<string> Adapters =
    [
        "nginx", "apache", "haproxy", "generic-file", "generic-ssh",
        "iis", "windows-cert-store", "windows-ccs",
        "java-keystore", "java-truststore", "oracle-wallet",
        "f5-bigip", "fortigate", "paloalto", "citrix-adc", "cisco-ise"
    ];

    private static IReadOnlyList<string> Build()
    {
        var capabilities = new List<string>
        {
            // SSH and SFTP are spoken by the runner's own library, not by an external binary,
            // so they are available wherever the runner runs.
            "ssh", "sftp"
        };

        // PowerShell is the Windows management channel (§11.1). On Windows the built-in host is
        // always there; elsewhere it exists only if PowerShell Core was installed.
        if (OperatingSystem.IsWindows())
        {
            capabilities.Add("powershell");
            capabilities.Add("winrm");
        }
        else if (Which("pwsh"))
        {
            capabilities.Add("powershell");
            // WinRM from a Linux runner goes over PowerShell Core remoting; without pwsh there
            // is no channel at all, so it is not advertised.
            capabilities.Add("winrm");
        }

        if (Which("openssl")) capabilities.Add("openssl");
        if (Which("keytool")) capabilities.Add("keytool");
        if (Which("orapki")) capabilities.Add("orapki");

        capabilities.AddRange(Adapters);
        return capabilities;
    }

    /// <summary>
    /// True when the named executable can be started. Runs it rather than searching PATH by hand
    /// so a shell alias, a wrapper script or a JDK on a non-standard path all answer correctly.
    /// </summary>
    private static bool Which(string executable)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(executable)
            {
                // keytool and orapki print usage and exit non-zero with no arguments; that still
                // proves they exist, which is all this is asking.
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            if (process is null) return false;
            if (!process.WaitForExit(5000))
            {
                // A tool that sits waiting for input is not usable unattended either.
                try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return false;
            }

            return true;
        }
        catch
        {
            // Not installed, not executable, or blocked — in every case the runner cannot use it.
            return false;
        }
    }
}
