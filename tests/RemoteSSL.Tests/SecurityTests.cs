using RemoteSSL.Application.Security;

namespace RemoteSSL.Tests;

/// <summary>Scope model of design doc §24.2.</summary>
public class ScopeEvaluatorTests
{
    private static readonly ScopeRequest ProdNginx =
        new("certificate.deploy", "PROD", "WEB", "nginx");

    [Fact]
    public void A_user_without_rules_is_not_restricted_by_scope()
    {
        Assert.True(ScopeEvaluator.IsAllowed([], ProdNginx));
    }

    [Fact]
    public void A_matching_rule_permits_the_request()
    {
        ScopeRule[] rules = [new("certificate.deploy", "PROD", "WEB", ["nginx", "iis"])];
        Assert.True(ScopeEvaluator.IsAllowed(rules, ProdNginx));
    }

    [Fact]
    public void A_rule_for_another_environment_does_not_permit_it()
    {
        ScopeRule[] rules = [new("certificate.deploy", "TEST")];
        Assert.False(ScopeEvaluator.IsAllowed(rules, ProdNginx));
    }

    [Fact]
    public void A_rule_for_another_target_group_does_not_permit_it()
    {
        ScopeRule[] rules = [new("certificate.deploy", "PROD", "DB")];
        Assert.False(ScopeEvaluator.IsAllowed(rules, ProdNginx));
    }

    [Fact]
    public void An_adapter_outside_the_rule_is_refused()
    {
        ScopeRule[] rules = [new("certificate.deploy", "PROD", "WEB", ["iis"])];
        Assert.False(ScopeEvaluator.IsAllowed(rules, ProdNginx));
    }

    [Fact]
    public void Null_fields_in_a_rule_mean_any()
    {
        ScopeRule[] rules = [new("certificate.deploy")];
        Assert.True(ScopeEvaluator.IsAllowed(rules, ProdNginx));
        Assert.True(ScopeEvaluator.IsAllowed(rules, new ScopeRequest("certificate.deploy", "DEV", "DB", "iis")));
    }

    [Fact]
    public void Rules_that_never_mention_the_action_refuse_it()
    {
        ScopeRule[] rules = [new("certificate.request", "PROD")];
        Assert.False(ScopeEvaluator.IsAllowed(rules, ProdNginx));
    }

    [Fact]
    public void Wildcards_widen_an_action_grant()
    {
        Assert.True(ScopeEvaluator.IsAllowed([new ScopeRule("certificate.*", "PROD")], ProdNginx));
        Assert.True(ScopeEvaluator.IsAllowed([new ScopeRule("*")], ProdNginx));
    }

    [Fact]
    public void The_approval_condition_is_honoured()
    {
        ScopeRule[] rules = [new("certificate.deploy", "PROD", ApprovalRequired: true)];
        Assert.False(ScopeEvaluator.IsAllowed(rules, ProdNginx with { ApprovalRequired = false }));
        Assert.True(ScopeEvaluator.IsAllowed(rules, ProdNginx with { ApprovalRequired = true }));
    }

    [Fact]
    public void Any_single_matching_rule_is_enough()
    {
        ScopeRule[] rules =
        [
            new("certificate.deploy", "TEST"),
            new("certificate.deploy", "PROD", "WEB")
        ];
        Assert.True(ScopeEvaluator.IsAllowed(rules, ProdNginx));
    }

    [Fact]
    public void Rules_parse_from_the_stored_json_shape()
    {
        var rules = ScopeEvaluator.Parse(
            """[{"action":"certificate.deploy","environment":"PROD","adapters":["nginx"]}]""");
        var rule = Assert.Single(rules);
        Assert.Equal("certificate.deploy", rule.Action);
        Assert.Equal("PROD", rule.Environment);
        Assert.Equal(["nginx"], rule.Adapters);
    }

    [Fact]
    public void Malformed_scope_json_grants_nothing_extra()
    {
        Assert.Empty(ScopeEvaluator.Parse("not json"));
        Assert.Empty(ScopeEvaluator.Parse(null));
    }
}

/// <summary>Adapter supply-chain controls of §30.2 / ADR-006.</summary>
public class AdapterAllowlistTests
{
    [Fact]
    public void No_configuration_means_no_restriction()
    {
        Assert.True(AdapterAllowlist.Check([], new Dictionary<string, string>(), "nginx", null).Allowed);
    }

    [Fact]
    public void An_adapter_outside_the_allowlist_is_refused_with_the_list_in_the_reason()
    {
        var verdict = AdapterAllowlist.Check(["nginx", "iis"], new Dictionary<string, string>(), "f5-bigip", null);
        Assert.False(verdict.Allowed);
        Assert.Contains("nginx", verdict.Reason);
    }

    [Fact]
    public void A_pinned_version_must_match_what_the_runner_reports()
    {
        var pins = new Dictionary<string, string> { ["nginx"] = "1.0.0" };

        Assert.True(AdapterAllowlist.Check([], pins, "nginx", """{"nginx":"1.0.0"}""").Allowed);

        var mismatch = AdapterAllowlist.Check([], pins, "nginx", """{"nginx":"0.9.0"}""");
        Assert.False(mismatch.Allowed);
        Assert.Contains("0.9.0", mismatch.Reason);
    }

    [Fact]
    public void A_runner_that_reports_no_version_for_a_pinned_adapter_is_refused()
    {
        var pins = new Dictionary<string, string> { ["nginx"] = "1.0.0" };
        var verdict = AdapterAllowlist.Check([], pins, "nginx", "{}");
        Assert.False(verdict.Allowed);
        Assert.Contains("did not report", verdict.Reason);
    }

    [Fact]
    public void Adapters_without_a_pin_are_unaffected_by_other_pins()
    {
        var pins = new Dictionary<string, string> { ["nginx"] = "1.0.0" };
        Assert.True(AdapterAllowlist.Check([], pins, "iis", "{}").Allowed);
    }
}
