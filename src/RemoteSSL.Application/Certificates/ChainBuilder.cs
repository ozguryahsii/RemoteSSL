using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace RemoteSSL.Application.Certificates;

/// <summary>One certificate in an assembled path, described for the UI.</summary>
public sealed record ChainLink(string Subject, string Issuer, string Sha256Thumbprint, bool SelfSigned, string Source);

/// <summary>
/// Result of chain assembly (§15.3): ordered paths, plus what is missing and where it could
/// be fetched from. Multiple paths appear when an issuer is cross-signed.
/// </summary>
public sealed record ChainAnalysis(
    IReadOnlyList<IReadOnlyList<ChainLink>> Paths,
    bool Complete,
    IReadOnlyList<string> MissingIssuers,
    IReadOnlyList<string> AiaUrls,
    IReadOnlyList<string> Warnings);

/// <summary>
/// Builds and inspects certificate chains for design doc §15.3 / FR-008: leaf issuer matched
/// to intermediate subject, ordered output, missing intermediates named (so a deployment can
/// be blocked before it breaks a service), AIA URLs surfaced for controlled retrieval, and
/// every trust path shown when an issuer is cross-signed.
/// </summary>
public static class ChainBuilder
{
    private const string AuthorityInfoAccessOid = "1.3.6.1.5.5.7.1.1";
    private const string CaIssuersAccessMethod = "1.3.6.1.5.5.7.48.2";

    /// <summary>
    /// Assembles every trust path that can be built from the supplied pool. The leaf comes
    /// first in each path; a path ends at a self-signed root or where the issuer is unknown.
    /// </summary>
    public static ChainAnalysis Analyze(string leafPem, string? poolPem)
    {
        using var leaf = X509Certificate2.CreateFromPem(leafPem);
        var pool = ParsePool(poolPem);

        var paths = new List<IReadOnlyList<ChainLink>>();
        var missing = new List<string>();
        var warnings = new List<string>();

        Walk(leaf, pool, [Describe(leaf, "leaf")], paths, missing, warnings, depth: 0);

        var complete = paths.Count > 0 && paths.Any(p => p[^1].SelfSigned);
        if (paths.Count > 1)
            warnings.Add($"The issuer is cross-signed: {paths.Count} trust paths are possible. "
                         + "Pick the one your target's trust store expects.");
        if (!complete && missing.Count == 0)
            warnings.Add("The chain ends without a self-signed root; the last certificate's issuer was not supplied.");

        return new ChainAnalysis(paths, complete, missing.Distinct().ToList(), AiaUrls(leaf), warnings);
    }

    /// <summary>
    /// Depth-first walk over every issuer candidate. Certificates already on the current path
    /// are skipped so a cross-signature loop cannot recurse forever.
    /// </summary>
    private static void Walk(
        X509Certificate2 current, IReadOnlyList<X509Certificate2> pool, List<ChainLink> path,
        List<IReadOnlyList<ChainLink>> paths, List<string> missing, List<string> warnings, int depth)
    {
        if (IsSelfSigned(current) || depth > 10)
        {
            paths.Add([.. path]);
            return;
        }

        var issuers = pool
            .Where(c => c.SubjectName.RawData.SequenceEqual(current.IssuerName.RawData))
            .Where(c => path.All(p => p.Sha256Thumbprint != Thumbprint(c)))
            .ToList();

        if (issuers.Count == 0)
        {
            missing.Add(current.Issuer);
            paths.Add([.. path]);
            return;
        }

        foreach (var issuer in issuers)
        {
            var branch = new List<ChainLink>(path) { Describe(issuer, "supplied") };
            if (issuer.NotAfter < DateTime.UtcNow)
                warnings.Add($"Intermediate '{issuer.Subject}' expired on {issuer.NotAfter:yyyy-MM-dd}.");
            Walk(issuer, pool, branch, paths, missing, warnings, depth + 1);
        }
    }

    /// <summary>
    /// Ordered PEM chain for deployment: the first complete path, root included only when asked.
    /// Throws when an intermediate is missing — a deployment must not ship a broken chain (§15.3).
    /// </summary>
    public static string BuildOrdered(string leafPem, string? poolPem, bool includeRoot = false)
    {
        var analysis = Analyze(leafPem, poolPem);
        if (analysis.MissingIssuers.Count > 0)
            throw new InvalidOperationException(
                "Chain is incomplete; missing issuer(s): " + string.Join(", ", analysis.MissingIssuers));

        var path = analysis.Paths.FirstOrDefault(p => p[^1].SelfSigned) ?? analysis.Paths.First();
        var pool = ParsePool(poolPem);
        var links = path.Skip(1) // the leaf is written separately by the caller
            .Where(l => includeRoot || !l.SelfSigned)
            .Select(l => pool.First(c => Thumbprint(c) == l.Sha256Thumbprint));

        return string.Join("\n", links.Select(c => new string(System.Security.Cryptography.PemEncoding.Write("CERTIFICATE", c.RawData))));
    }

    /// <summary>CA Issuers URLs from the Authority Information Access extension (§15.3).</summary>
    public static IReadOnlyList<string> AiaUrls(X509Certificate2 cert)
    {
        var extension = cert.Extensions[AuthorityInfoAccessOid];
        if (extension is null) return [];

        try
        {
            var urls = new List<string>();
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (reader.HasData)
            {
                var description = reader.ReadSequence();
                var method = description.ReadObjectIdentifier();
                // GeneralName [6] = uniformResourceIdentifier
                var tag = new Asn1Tag(TagClass.ContextSpecific, 6);
                if (!description.PeekTag().HasSameClassAndValue(tag)) continue;
                var url = description.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                if (method == CaIssuersAccessMethod) urls.Add(url);
            }
            return urls;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }

    private static ChainLink Describe(X509Certificate2 cert, string source) =>
        new(cert.Subject, cert.Issuer, Thumbprint(cert), IsSelfSigned(cert), source);

    private static string Thumbprint(X509Certificate2 cert) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData));

    private static bool IsSelfSigned(X509Certificate2 cert) =>
        cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData);

    private static List<X509Certificate2> ParsePool(string? poolPem) =>
        CertificateFactory.ParsePemCertificates(poolPem).ToList();
}
