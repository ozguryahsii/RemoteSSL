using System.Globalization;
using System.Text.RegularExpressions;
using RemoteSSL.Adapters.Ssh;

namespace RemoteSSL.Adapters.Java;

/// <summary>One entry found in a keystore (design doc §12.3).</summary>
/// <param name="EntryType">"PrivateKeyEntry" or "trustedCertEntry" as keytool reports it.</param>
public sealed record JavaKeystoreEntry(
    string Alias, string EntryType, string? Subject, string? Issuer,
    string? SerialNumber, string? Sha256Thumbprint, DateTimeOffset? NotAfter);

/// <summary>What a store discovery pass found.</summary>
public sealed record JavaKeystoreInventoryResult(
    bool Success, string StorePath, string StoreType,
    IReadOnlyList<JavaKeystoreEntry> Entries, string? Error);

/// <summary>
/// Reads what is actually in a Java keystore (design doc §12.3). Deployment only ever touches one
/// alias, so without this a store's other entries — expired trust anchors, forgotten key pairs —
/// stay invisible to the inventory. The pass is read-only: it runs <c>keytool -list -v</c> and
/// parses it, and never modifies the store.
/// </summary>
public static class JavaKeystoreInventory
{
    public sealed class InventoryPayload
    {
        public SshTargetConfig Connection { get; set; } = new("localhost");
        public Guid? CredentialRefId { get; set; }
        public string StorePath { get; set; } = string.Empty;
        public string StoreType { get; set; } = "JKS";
        public string StorePassword { get; set; } = string.Empty;
        public string? KeytoolPath { get; set; }
    }

    public static JavaKeystoreInventoryResult Inventory(InventoryPayload p, SshCredentials creds)
    {
        using var ssh = new SshConnection(p.Connection, creds);
        try
        {
            ssh.Connect();
        }
        catch (Exception ex)
        {
            return new JavaKeystoreInventoryResult(false, p.StorePath, p.StoreType, [], $"ssh connect failed: {ex.Message}");
        }

        if (!ssh.FileExists(p.StorePath))
            return new JavaKeystoreInventoryResult(false, p.StorePath, p.StoreType, [], "keystore not found on the target");

        var keytool = p.KeytoolPath ?? "keytool";
        // The password goes through the environment, never onto a command line where ps would show it.
        var env = $"KEYTOOL_SP={Shell.Quote(p.StorePassword)}";
        var listing = ssh.Exec(
            $"{env} {keytool} -list -v -keystore {Shell.Quote(p.StorePath)} "
            + $"-storetype {p.StoreType} -storepass:env KEYTOOL_SP 2>&1");

        if (!listing.Ok)
            return new JavaKeystoreInventoryResult(false, p.StorePath, p.StoreType, [],
                Trunc(listing.Stdout + listing.Stderr));

        return new JavaKeystoreInventoryResult(true, p.StorePath, p.StoreType, Parse(listing.Stdout), null);
    }

    private static readonly Regex AliasLine = new(@"^Alias name:\s*(?<alias>.+?)\s*$", RegexOptions.Multiline);
    private static readonly Regex TypeLine = new(@"^Entry type:\s*(?<type>\S+)", RegexOptions.Multiline);
    private static readonly Regex OwnerLine = new(@"^Owner:\s*(?<dn>.+?)\s*$", RegexOptions.Multiline);
    private static readonly Regex IssuerLine = new(@"^Issuer:\s*(?<dn>.+?)\s*$", RegexOptions.Multiline);
    private static readonly Regex SerialLine = new(@"^Serial number:\s*(?<serial>\S+)", RegexOptions.Multiline);
    private static readonly Regex ValidLine = new(@"until:\s*(?<until>.+?)\s*$", RegexOptions.Multiline);
    private static readonly Regex Sha256Line = new(@"SHA256:\s*(?<fp>[0-9A-Fa-f:]{47,})", RegexOptions.Multiline);

    /// <summary>
    /// Parses <c>keytool -list -v</c> output. Entries are separated by a run of asterisks, and
    /// every field is optional — a truststore entry has no key, and locales vary — so anything
    /// that cannot be read is left null rather than guessed at.
    /// </summary>
    public static IReadOnlyList<JavaKeystoreEntry> Parse(string output)
    {
        var entries = new List<JavaKeystoreEntry>();
        // Each entry begins at its "Alias name:" line and runs until the next one.
        var starts = AliasLine.Matches(output);
        for (var i = 0; i < starts.Count; i++)
        {
            var start = starts[i].Index;
            var end = i + 1 < starts.Count ? starts[i + 1].Index : output.Length;
            var block = output[start..end];

            entries.Add(new JavaKeystoreEntry(
                starts[i].Groups["alias"].Value.Trim(),
                Value(TypeLine, block) ?? "unknown",
                Value(OwnerLine, block),
                Value(IssuerLine, block),
                Value(SerialLine, block),
                Value(Sha256Line, block, "fp")?.Replace(":", string.Empty).ToUpperInvariant(),
                ParseDate(Value(ValidLine, block, "until"))));
        }
        return entries;
    }

    private static string? Value(Regex regex, string block, string group = "")
    {
        var match = regex.Match(block);
        if (!match.Success) return null;
        var name = group.Length > 0 ? group : regex.GetGroupNames().Last(n => n != "0");
        return match.Groups[name].Value.Trim() is { Length: > 0 } v ? v : null;
    }

    /// <summary>Zone abbreviation before the year, e.g. "UTC" in "… 10:00:00 UTC 2026".</summary>
    private static readonly Regex ZoneAbbreviation = new(@"\s+(?<zone>[A-Z]{2,5})\s+(?<year>\d{4})\s*$");

    /// <summary>
    /// keytool prints dates in the JVM's locale and time zone, typically as
    /// "Sun Aug 02 10:00:00 UTC 2026". A numeric offset parses directly; a zone abbreviation does
    /// not map reliably to an offset from a name alone, so it is dropped and the time read as UTC —
    /// good to the day, which is what an expiry is used for. Anything unparseable becomes null
    /// rather than a wrong date.
    /// </summary>
    private static DateTimeOffset? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string[] formats =
        [
            "ddd MMM dd HH:mm:ss zzz yyyy",
            "ddd MMM dd HH:mm:ss yyyy",
            "MMM d, yyyy h:mm:ss tt",
            "yyyy-MM-dd HH:mm:ss"
        ];

        var candidate = ZoneAbbreviation.Replace(value, m => " " + m.Groups["year"].Value);
        if (DateTimeOffset.TryParseExact(candidate, formats, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var exact))
            return exact;
        return DateTimeOffset.TryParse(candidate, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var loose) ? loose : null;
    }

    private static string Trunc(string s) => s.Length <= 400 ? s : s[..400];
}
