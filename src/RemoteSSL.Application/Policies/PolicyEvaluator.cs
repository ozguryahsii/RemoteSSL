using System.Text.Json;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Policies;

/// <summary>A single rule outcome. Blocking violations stop the request; warnings only inform.</summary>
public sealed record PolicyFinding(string Rule, string Message, bool Blocking);

/// <summary>What a request is asking for, independent of persistence.</summary>
public sealed record RequestFacts(
    string CommonName,
    IReadOnlyList<string> Sans,
    string KeyAlgorithm,
    int KeySizeOrCurve,
    string? OwnerId = null,
    int? RequestedValidityDays = null,
    IReadOnlyList<string>? OverlappingCertificates = null);

/// <summary>
/// Enforces the certificate policy of design doc §39 and the request validation rules of
/// §17.2. Pure functions over the policy so the same decisions can be unit-tested and reused
/// by the request wizard, the renewal engine and the deployment orchestrator alike.
/// </summary>
public static class PolicyEvaluator
{
    /// <summary>Signature algorithms considered weak; blocked when the policy says so (§39).</summary>
    private static readonly string[] WeakSignatureMarkers = ["md5", "sha1"];

    public static IReadOnlyList<PolicyFinding> ValidateRequest(CertificatePolicy policy, RequestFacts facts)
    {
        var findings = new List<PolicyFinding>();
        var names = new List<string> { facts.CommonName };
        names.AddRange(facts.Sans);
        names = names.Select(n => n.Trim().ToLowerInvariant()).Where(n => n.Length > 0).Distinct().ToList();

        // Key strength (§39 minimumRsaBits / allowedEcCurves)
        if (facts.KeyAlgorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase))
        {
            if (facts.KeySizeOrCurve < policy.MinimumRsaBits)
                findings.Add(new("key.rsa-size",
                    $"RSA key size {facts.KeySizeOrCurve} is below the policy minimum {policy.MinimumRsaBits}.", true));
        }
        else if (facts.KeyAlgorithm.Equals("EC", StringComparison.OrdinalIgnoreCase))
        {
            var allowed = ParseList(policy.AllowedEcCurvesJson);
            var curve = CurveName(facts.KeySizeOrCurve);
            if (allowed.Count > 0 && !allowed.Any(c => c.Equals(curve, StringComparison.OrdinalIgnoreCase)))
                findings.Add(new("key.ec-curve",
                    $"EC curve {curve} is not in the allowed set ({string.Join(", ", allowed)}).", true));
        }
        else
        {
            findings.Add(new("key.algorithm", $"Unsupported key algorithm '{facts.KeyAlgorithm}'.", true));
        }

        // Wildcard policy (§17.2)
        if (!policy.AllowWildcard && names.Any(n => n.StartsWith("*.", StringComparison.Ordinal)))
            findings.Add(new("name.wildcard", "Wildcard names are not permitted by policy.", true));

        // Internal / public hostname policy (§17.2)
        var blocked = ParseList(policy.BlockedDomainSuffixesJson);
        foreach (var name in names)
        {
            var hit = blocked.FirstOrDefault(s => name.EndsWith(s.Trim().ToLowerInvariant(), StringComparison.Ordinal));
            if (hit is not null)
                findings.Add(new("name.blocked-suffix", $"'{name}' ends with a blocked suffix '{hit}'.", true));
        }

        var allowedSuffixes = ParseList(policy.AllowedDomainSuffixesJson);
        if (allowedSuffixes.Count > 0)
        {
            foreach (var name in names.Where(name =>
                         !allowedSuffixes.Any(s => name.EndsWith(s.Trim().ToLowerInvariant(), StringComparison.Ordinal))))
                findings.Add(new("name.allowed-suffix",
                    $"'{name}' is outside the permitted domains ({string.Join(", ", allowedSuffixes)}).", true));
        }

        // Maximum validity / CA profile limit (§17.2)
        if (policy.MaxValidityDays is { } max && facts.RequestedValidityDays is { } requested && requested > max)
            findings.Add(new("validity.max",
                $"Requested validity {requested} days exceeds the policy maximum {max} days.", true));

        // Ownership policy (§17.2)
        if (policy.RequireOwner && string.IsNullOrWhiteSpace(facts.OwnerId))
            findings.Add(new("ownership.required", "Policy requires an owner on every certificate request.", true));

        // Existing certificate overlap warning (§17.2)
        if (policy.WarnOnOverlap && facts.OverlappingCertificates is { Count: > 0 } overlaps)
            findings.Add(new("name.overlap",
                $"These names are already covered by: {string.Join(", ", overlaps.Take(5))}.", false));

        return findings;
    }

    /// <summary>SAN duplicate normalization of §17.2: lower-cased, trimmed, CN first, no repeats.</summary>
    public static IReadOnlyList<string> NormalizeNames(string commonName, IEnumerable<string> sans)
    {
        var cn = commonName.Trim().ToLowerInvariant();
        var result = new List<string> { cn };
        result.AddRange(sans.Select(s => s.Trim().ToLowerInvariant()).Where(s => s.Length > 0));
        return result.Distinct().ToList();
    }

    /// <summary>§23.2: does this environment need maker-checker approval?</summary>
    public static bool RequiresApproval(CertificatePolicy policy, string? environment) =>
        MatchesEnvironment(policy.RequireApprovalInJson, environment);

    /// <summary>§23.2: does this environment only deploy inside a maintenance window?</summary>
    public static bool RequiresMaintenanceWindow(CertificatePolicy policy, string? environment) =>
        MatchesEnvironment(policy.RequireWindowInJson, environment);

    /// <summary>§39 blockWeakSignatureAlgorithms — true when the algorithm must be refused.</summary>
    public static bool IsWeakSignature(CertificatePolicy policy, string? signatureAlgorithm) =>
        policy.BlockWeakSignatureAlgorithms
        && signatureAlgorithm is not null
        && WeakSignatureMarkers.Any(w => signatureAlgorithm.Replace("-", "").Contains(w, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// §23.3 separation of duties: the requester may not approve their own change. A
    /// break-glass administrator may, and the caller must audit that as an exception.
    /// </summary>
    public static bool IsSelfApproval(CertificatePolicy policy, string? requestedBy, string? approver) =>
        policy.EnforceSeparationOfDuties
        && !string.IsNullOrWhiteSpace(requestedBy)
        && string.Equals(requestedBy, approver, StringComparison.OrdinalIgnoreCase);

    private static bool MatchesEnvironment(string json, string? environment)
    {
        if (string.IsNullOrWhiteSpace(environment)) return false;
        return ParseList(json).Any(e => e.Equals(environment, StringComparison.OrdinalIgnoreCase));
    }

    private static string CurveName(int keySizeOrCurve) => keySizeOrCurve switch
    {
        256 => "P-256",
        384 => "P-384",
        521 => "P-521",
        _ => $"P-{keySizeOrCurve}"
    };

    private static List<string> ParseList(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

/// <summary>Raised when a blocking policy rule refuses a request (§17.2, §39).</summary>
public class PolicyViolationException(IReadOnlyList<PolicyFinding> findings)
    : Exception("Policy violation: " + string.Join(" ", findings.Where(f => f.Blocking).Select(f => f.Message)))
{
    public IReadOnlyList<PolicyFinding> Findings { get; } = findings;
}
