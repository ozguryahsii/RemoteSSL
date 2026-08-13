using RemoteSSL.Application.Policies;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Tests;

public class PolicyEvaluatorTests
{
    private static CertificatePolicy Policy() => new() { Name = "test" };

    private static RequestFacts Facts(
        string cn = "app.company.com", string[]? sans = null, string alg = "RSA", int size = 2048,
        string? owner = null, int? validity = null, string[]? overlaps = null) =>
        new(cn, sans ?? [], alg, size, owner, validity, overlaps);

    [Fact]
    public void Rsa_below_the_policy_minimum_is_blocked()
    {
        var findings = PolicyEvaluator.ValidateRequest(Policy(), Facts(size: 1024));
        Assert.Contains(findings, f => f.Rule == "key.rsa-size" && f.Blocking);
    }

    [Fact]
    public void Compliant_rsa_request_passes()
    {
        Assert.Empty(PolicyEvaluator.ValidateRequest(Policy(), Facts()));
    }

    [Fact]
    public void Ec_curve_outside_the_allowed_set_is_blocked()
    {
        var findings = PolicyEvaluator.ValidateRequest(Policy(), Facts(alg: "EC", size: 521));
        Assert.Contains(findings, f => f.Rule == "key.ec-curve" && f.Blocking);
    }

    [Fact]
    public void Allowed_ec_curve_passes()
    {
        Assert.Empty(PolicyEvaluator.ValidateRequest(Policy(), Facts(alg: "EC", size: 256)));
    }

    [Fact]
    public void Wildcard_is_blocked_when_policy_forbids_it()
    {
        var policy = Policy();
        policy.AllowWildcard = false;
        var findings = PolicyEvaluator.ValidateRequest(policy, Facts(cn: "*.company.com"));
        Assert.Contains(findings, f => f.Rule == "name.wildcard" && f.Blocking);
    }

    [Fact]
    public void Blocked_suffix_refuses_internal_names()
    {
        var policy = Policy();
        policy.BlockedDomainSuffixesJson = """[".local"]""";
        var findings = PolicyEvaluator.ValidateRequest(policy, Facts(cn: "db.corp.local"));
        Assert.Contains(findings, f => f.Rule == "name.blocked-suffix" && f.Blocking);
    }

    [Fact]
    public void Allowed_suffix_list_refuses_names_outside_it()
    {
        var policy = Policy();
        policy.AllowedDomainSuffixesJson = """["company.com"]""";
        var findings = PolicyEvaluator.ValidateRequest(policy, Facts(cn: "app.company.com", sans: ["api.other.net"]));
        Assert.Contains(findings, f => f.Rule == "name.allowed-suffix" && f.Blocking);
        Assert.DoesNotContain(findings, f => f.Message.Contains("app.company.com"));
    }

    [Fact]
    public void Validity_above_the_maximum_is_blocked()
    {
        var policy = Policy();
        policy.MaxValidityDays = 397;
        var findings = PolicyEvaluator.ValidateRequest(policy, Facts(validity: 730));
        Assert.Contains(findings, f => f.Rule == "validity.max" && f.Blocking);
    }

    [Fact]
    public void Missing_owner_is_blocked_only_when_the_policy_requires_one()
    {
        var policy = Policy();
        Assert.Empty(PolicyEvaluator.ValidateRequest(policy, Facts()));
        policy.RequireOwner = true;
        Assert.Contains(PolicyEvaluator.ValidateRequest(policy, Facts()),
            f => f.Rule == "ownership.required" && f.Blocking);
    }

    [Fact]
    public void Overlap_is_a_warning_not_a_block()
    {
        var findings = PolicyEvaluator.ValidateRequest(Policy(), Facts(overlaps: ["*.company.com"]));
        var overlap = Assert.Single(findings);
        Assert.Equal("name.overlap", overlap.Rule);
        Assert.False(overlap.Blocking);
    }

    [Fact]
    public void Names_are_normalized_with_the_common_name_first_and_no_duplicates()
    {
        var names = PolicyEvaluator.NormalizeNames("App.Company.com", [" api.company.com ", "APP.company.com", ""]);
        Assert.Equal(["app.company.com", "api.company.com"], names);
    }

    [Fact]
    public void Approval_is_required_only_in_the_listed_environments()
    {
        var policy = Policy();
        policy.RequireApprovalInJson = """["PROD"]""";
        Assert.True(PolicyEvaluator.RequiresApproval(policy, "PROD"));
        Assert.True(PolicyEvaluator.RequiresApproval(policy, "prod"));
        Assert.False(PolicyEvaluator.RequiresApproval(policy, "DEV"));
        Assert.False(PolicyEvaluator.RequiresApproval(policy, null));
    }

    [Theory]
    [InlineData("sha1RSA", true)]
    [InlineData("md5RSA", true)]
    [InlineData("sha256RSA", false)]
    public void Weak_signature_algorithms_are_recognised(string algorithm, bool weak)
    {
        Assert.Equal(weak, PolicyEvaluator.IsWeakSignature(Policy(), algorithm));
    }

    [Fact]
    public void Weak_signature_check_is_off_when_the_policy_disables_it()
    {
        var policy = Policy();
        policy.BlockWeakSignatureAlgorithms = false;
        Assert.False(PolicyEvaluator.IsWeakSignature(policy, "sha1RSA"));
    }
}

public class SeparationOfDutiesTests
{
    private static CertificatePolicy Policy() => new() { Name = "test" };

    [Fact]
    public void Approving_someone_elses_change_is_allowed()
    {
        Assert.Equal(ApproverDecision.Allowed,
            GovernanceService.CheckApprover(Policy(), "adnan", "approver", false));
    }

    [Fact]
    public void Self_approval_is_refused()
    {
        Assert.Equal(ApproverDecision.SelfApprovalRefused,
            GovernanceService.CheckApprover(Policy(), "adnan", "adnan", false));
    }

    [Fact]
    public void Break_glass_may_self_approve_and_is_flagged_as_such()
    {
        Assert.Equal(ApproverDecision.BreakGlass,
            GovernanceService.CheckApprover(Policy(), "adnan", "adnan", true));
    }

    [Fact]
    public void Self_approval_is_allowed_when_the_policy_does_not_enforce_it()
    {
        var policy = Policy();
        policy.EnforceSeparationOfDuties = false;
        Assert.Equal(ApproverDecision.Allowed,
            GovernanceService.CheckApprover(policy, "adnan", "adnan", false));
    }
}

public class CertificateStatusResolverTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Revoked_outranks_everything_including_a_long_validity()
    {
        Assert.Equal(CertificateHealthStatus.Revoked,
            CertificateStatusResolver.Resolve(CertificateHealthStatus.Revoked, Now.AddDays(300), Now));
    }

    [Fact]
    public void Expiry_wins_over_a_deployment_state_once_the_certificate_expired()
    {
        Assert.Equal(CertificateHealthStatus.Expired,
            CertificateStatusResolver.Resolve(CertificateHealthStatus.PartiallyDeployed, Now.AddDays(-1), Now));
    }

    [Fact]
    public void Deployment_state_is_shown_while_the_certificate_is_still_valid()
    {
        Assert.Equal(CertificateHealthStatus.PartiallyDeployed,
            CertificateStatusResolver.Resolve(CertificateHealthStatus.PartiallyDeployed, Now.AddDays(200), Now));
    }

    [Fact]
    public void A_healthy_certificate_falls_back_to_the_expiry_derived_status()
    {
        Assert.Equal(CertificateHealthStatus.ExpiringSoon,
            CertificateStatusResolver.Resolve(CertificateHealthStatus.Healthy, Now.AddDays(20), Now));
    }

    [Fact]
    public void Job_outcomes_map_onto_lifecycle_statuses()
    {
        Assert.Equal(CertificateHealthStatus.PendingDeployment,
            CertificateStatusResolver.FromDeployment(DeploymentJobStatus.Running));
        Assert.Equal(CertificateHealthStatus.PartiallyDeployed,
            CertificateStatusResolver.FromDeployment(DeploymentJobStatus.PartiallyFailed));
        Assert.Equal(CertificateHealthStatus.DeploymentFailed,
            CertificateStatusResolver.FromDeployment(DeploymentJobStatus.RollbackFailed));
        Assert.Equal(CertificateHealthStatus.Healthy,
            CertificateStatusResolver.FromDeployment(DeploymentJobStatus.Succeeded));
    }
}

public class MaintenanceWindowTests
{
    [Fact]
    public void Inside_the_window_is_open()
    {
        var sunday0200 = new DateTimeOffset(2026, 8, 16, 2, 0, 0, TimeSpan.Zero);
        Assert.True(MaintenanceWindow.IsOpen("""{"days":["SUN"],"start":"01:00","end":"04:00"}""", sunday0200));
    }

    [Fact]
    public void Wrong_day_is_closed()
    {
        var monday0200 = new DateTimeOffset(2026, 8, 17, 2, 0, 0, TimeSpan.Zero);
        Assert.False(MaintenanceWindow.IsOpen("""{"days":["SUN"],"start":"01:00","end":"04:00"}""", monday0200));
    }

    [Fact]
    public void Window_crossing_midnight_stays_open_after_midnight()
    {
        var sunday0030 = new DateTimeOffset(2026, 8, 16, 0, 30, 0, TimeSpan.Zero);
        Assert.True(MaintenanceWindow.IsOpen("""{"days":["SUN"],"start":"22:00","end":"02:00"}""", sunday0030));
    }
}
