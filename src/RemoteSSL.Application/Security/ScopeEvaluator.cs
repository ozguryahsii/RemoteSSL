using System.Text.Json;

namespace RemoteSSL.Application.Security;

/// <summary>
/// One permission grant in the scope model of design doc §24.2. A null field means
/// "any", so an empty rule grants the action everywhere — which is why an operator
/// who has no rules at all is treated as unrestricted-by-role rather than granted here.
/// </summary>
public sealed record ScopeRule(
    string Action,
    string? Environment = null,
    string? TargetGroup = null,
    IReadOnlyList<string>? Adapters = null,
    bool? ApprovalRequired = null);

/// <summary>What is being attempted, described in the terms §24.2 uses.</summary>
public sealed record ScopeRequest(
    string Action,
    string? Environment = null,
    string? TargetGroup = null,
    string? Adapter = null,
    bool ApprovalRequired = false);

/// <summary>
/// Attribute-based authorization on top of roles (§24.2): a role says what kind of work a
/// user does, a scope says where they may do it — environment, target group, adapter, and
/// whether the change carries approval. Roles alone were not enough for the document's
/// model, which is why this sits beside them rather than replacing them.
/// </summary>
public static class ScopeEvaluator
{
    /// <summary>
    /// True when at least one rule permits the request. A user with no rules is not
    /// restricted by scope at all — their roles decide, which keeps existing installs
    /// working exactly as before scopes existed.
    /// </summary>
    public static bool IsAllowed(IReadOnlyList<ScopeRule> rules, ScopeRequest request)
    {
        if (rules.Count == 0) return true;

        var applicable = rules.Where(r => ActionMatches(r.Action, request.Action)).ToList();
        // Rules exist but none mention this action: the user was scoped for other work.
        if (applicable.Count == 0) return false;

        return applicable.Any(rule => Matches(rule, request));
    }

    private static bool Matches(ScopeRule rule, ScopeRequest request) =>
        ValueMatches(rule.Environment, request.Environment)
        && ValueMatches(rule.TargetGroup, request.TargetGroup)
        && AdapterMatches(rule.Adapters, request.Adapter)
        && (rule.ApprovalRequired is not { } required || required == request.ApprovalRequired);

    /// <summary>
    /// "certificate.deploy" matches exactly; "certificate.*" and "*" widen it. Wildcards are
    /// prefix-based so a grant can cover a family of actions without listing each one.
    /// </summary>
    private static bool ActionMatches(string rule, string requested)
    {
        if (rule == "*") return true;
        if (rule.EndsWith(".*", StringComparison.Ordinal))
            return requested.StartsWith(rule[..^1], StringComparison.OrdinalIgnoreCase);
        return string.Equals(rule, requested, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ValueMatches(string? ruleValue, string? requestValue)
    {
        if (ruleValue is null) return true;                 // rule says "any"
        if (requestValue is null) return false;             // rule is specific, request is not
        return string.Equals(ruleValue, requestValue, StringComparison.OrdinalIgnoreCase);
    }

    private static bool AdapterMatches(IReadOnlyList<string>? allowed, string? adapter)
    {
        if (allowed is null || allowed.Count == 0) return true;
        if (adapter is null) return false;
        return allowed.Any(a => string.Equals(a, adapter, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Reads the rules stored on a user; malformed JSON grants nothing extra.</summary>
    public static IReadOnlyList<ScopeRule> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<ScopeRule>>(json,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
