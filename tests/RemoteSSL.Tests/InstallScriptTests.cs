using System.Text;

namespace RemoteSSL.Tests;

/// <summary>
/// The Windows installer has to survive the shell that will actually run it.
///
/// Windows PowerShell 5.1 — still the default on Windows Server — reads a script with no
/// byte-order mark as ANSI, not UTF-8. A single em dash in a comment then decodes to three
/// characters, one of which is a curly quote, and PowerShell treats curly quotes as string
/// delimiters: the file fails to parse before a line of it runs. That is exactly what happened on
/// the first real install, so both halves of the rule are checked here.
/// </summary>
public class InstallScriptTests
{
    public static TheoryData<string> Scripts()
    {
        var data = new TheoryData<string>();
        foreach (var file in Directory.GetFiles(Path.Combine(RepositoryRoot(), "deploy"), "*.ps1",
                     SearchOption.AllDirectories))
            data.Add(file);
        return data;
    }

    [Theory]
    [MemberData(nameof(Scripts))]
    public void A_powershell_script_carries_a_byte_order_mark(string path)
    {
        var bytes = File.ReadAllBytes(path);

        Assert.True(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF,
            $"{Path.GetFileName(path)} has no UTF-8 BOM, so Windows PowerShell 5.1 will read it as ANSI.");
    }

    [Theory]
    [MemberData(nameof(Scripts))]
    public void A_powershell_script_is_otherwise_plain_ascii(string path)
    {
        var text = File.ReadAllText(path, Encoding.UTF8);

        // The BOM itself is the one character above ASCII that belongs here.
        var offenders = text.Where(c => c > 127 && c != '﻿').Distinct().ToList();

        Assert.True(offenders.Count == 0,
            $"{Path.GetFileName(path)} contains {string.Join(" ", offenders.Select(c => $"U+{(int)c:X4}"))}. "
            + "Use ASCII: an installer is read by whichever PowerShell the server happens to have.");
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "RemoteSSL.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("RemoteSSL.sln not found above the test binary");
    }
}
