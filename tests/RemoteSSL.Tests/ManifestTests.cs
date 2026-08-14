using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Deployments;
using RemoteSSL.Application.Policies;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;
using RemoteSSL.Infrastructure.Persistence;

namespace RemoteSSL.Tests;

/// <summary>
/// The declarative manifest of design doc §38. A manifest is meant to live in a git repository
/// next to the service it renews, so the tests are mostly about the two things that make that
/// safe: a malformed or ambiguous file is refused with a reason an operator can act on, and a
/// selector never silently matches more or fewer targets than it says.
/// </summary>
public class ManifestParserTests
{
    private const string Valid = """
        apiVersion: remotessl/v1
        kind: CertificateDeployment
        metadata:
          name: web-tier-renewal
        spec:
          certificate:
            commonName: www.example.com
            version: latest
          targets:
            - environment: production
              adapter: nginx
          strategy:
            type: wave
            maxConcurrency: 3
          verification:
            remoteTlsVerify: true
            host: www.example.com
            port: 443
        """;

    [Fact]
    public void A_well_formed_manifest_parses_into_every_field_it_declares()
    {
        var result = ManifestParser.Parse(Valid);

        Assert.True(result.Ok, string.Join("; ", result.Errors));
        var spec = result.Manifest!.Spec!;
        Assert.Equal("web-tier-renewal", result.Manifest.Metadata!.Name);
        Assert.Equal("www.example.com", spec.Certificate!.CommonName);
        Assert.Equal("latest", spec.Certificate.Version);
        Assert.Equal("wave", spec.Strategy!.Type);
        Assert.Equal(3, spec.Strategy.MaxConcurrency);
        Assert.Equal(443, spec.Verification!.Port);
        var selector = Assert.Single(spec.Targets);
        Assert.Equal("production", selector.Environment);
        Assert.Equal("nginx", selector.Adapter);
    }

    [Fact]
    public void A_manifest_for_another_tool_is_refused_by_apiVersion_and_kind()
    {
        // The two header fields exist so a file meant for something else cannot be applied here.
        var result = ManifestParser.Parse("""
            apiVersion: apps/v1
            kind: Deployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - name: web-01
            """);

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("apiVersion"));
        Assert.Contains(result.Errors, e => e.Contains("kind"));
    }

    [Fact]
    public void Broken_yaml_is_reported_with_the_line_it_failed_on()
    {
        // A hand-written file needs a location, not just "invalid".
        var result = ManifestParser.Parse("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              targets:
              - name: web-01
               badly: indented
            """);

        Assert.False(result.Ok);
        Assert.Contains("Line", Assert.Single(result.Errors));
    }

    [Fact]
    public void Every_problem_is_reported_at_once_rather_than_one_per_attempt()
    {
        var result = ManifestParser.Parse("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                version: sometime
              targets: []
              strategy:
                type: blue-green
            """);

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("commonName or thumbprint"));
        Assert.Contains(result.Errors, e => e.Contains("version"));
        Assert.Contains(result.Errors, e => e.Contains("at least one target"));
        Assert.Contains(result.Errors, e => e.Contains("blue-green"));
    }

    [Fact]
    public void A_certificate_named_two_ways_at_once_is_refused_rather_than_guessed()
    {
        var result = ManifestParser.Parse("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
                thumbprint: AABBCC
              targets:
                - name: web-01
            """);

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("exactly one"));
    }

    [Fact]
    public void A_selector_with_no_criteria_is_refused_because_it_would_match_everything()
    {
        // The most expensive possible typo: an empty selector deploying to the whole estate.
        var result = ManifestParser.Parse("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - {}
            """);

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("match every target"));
    }

    [Fact]
    public void Every_strategy_the_orchestrator_implements_is_accepted_by_the_manifest()
    {
        // A strategy the engine supports but the manifest rejects would be invisible to anyone
        // working from the file rather than the UI.
        foreach (var strategy in ManifestParser.KnownStrategies)
        {
            var result = ManifestParser.Parse($"""
                apiVersion: remotessl/v1
                kind: CertificateDeployment
                spec:
                  certificate:
                    commonName: www.example.com
                  targets:
                    - name: web-01
                  strategy:
                    type: {strategy}
                """);

            Assert.True(result.Ok, $"'{strategy}' was rejected: {string.Join("; ", result.Errors)}");
        }
    }
}

/// <summary>
/// Resolution: turning the names in a manifest into the rows a deployment actually runs against.
/// </summary>
public class ManifestResolutionTests
{
    private static RemoteSslDbContext CreateDb() =>
        new(new DbContextOptionsBuilder<RemoteSslDbContext>()
            .UseInMemoryDatabase($"manifest-tests-{Guid.NewGuid()}").Options);

    private static ManifestService Service(RemoteSslDbContext db) =>
        new(db, new DeploymentPlanner(db, new GovernanceService(db)), null!, null!);

    /// <summary>
    /// One certificate with an active version, and three bound targets: two production nginx
    /// (one of them a standby) and one staging.
    /// </summary>
    private static async Task<RemoteSslDbContext> SeededAsync(string commonName = "www.example.com")
    {
        var db = CreateDb();
        var certificate = new Certificate
        {
            Id = Guid.NewGuid(), CommonName = commonName, Environment = "production"
        };
        db.Certificates.Add(certificate);
        db.CertificateVersions.Add(new CertificateVersion
        {
            Id = Guid.NewGuid(), CertificateId = certificate.Id, Certificate = certificate,
            Status = CertificateVersionStatus.Active, Sha256Thumbprint = new string('A', 64),
            NotBefore = DateTimeOffset.UtcNow.AddDays(-1), NotAfter = DateTimeOffset.UtcNow.AddDays(89)
        });

        foreach (var (name, environment, adapter, group, haRole) in new[]
                 {
                     ("web-01", "production", "nginx", "web-tier", "active"),
                     ("web-02", "production", "nginx", "web-tier", "standby"),
                     ("stage-01", "staging", "nginx", "web-tier", (string?)null)
                 })
        {
            var target = new Target
            {
                Id = Guid.NewGuid(), Name = name, Environment = environment, AdapterType = adapter,
                TargetGroup = group, HaRole = haRole
            };
            var store = new CertificateStore
            {
                Id = Guid.NewGuid(), TargetId = target.Id, Target = target,
                StoreType = "pem-file", StorePath = $"/etc/ssl/{name}.pem"
            };
            db.Targets.Add(target);
            db.CertificateStores.Add(store);
            db.DeploymentBindings.Add(new DeploymentBinding
            {
                Id = Guid.NewGuid(), CertificateId = certificate.Id, Certificate = certificate,
                CertificateStoreId = store.Id, CertificateStore = store
            });
        }

        await db.SaveChangesAsync();
        return db;
    }

    private static DeploymentManifest Manifest(string yaml)
    {
        var parsed = ManifestParser.Parse(yaml);
        Assert.True(parsed.Ok, string.Join("; ", parsed.Errors));
        return parsed.Manifest!;
    }

    [Fact]
    public async Task A_label_selector_resolves_to_exactly_the_targets_it_describes()
    {
        await using var db = await SeededAsync();

        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - environment: production
                  adapter: nginx
            """), default);

        Assert.True(resolution.Ok, string.Join("; ", resolution.Errors));
        Assert.Equal(["web-01", "web-02"], resolution.Targets.Select(t => t.Target).Order());
    }

    [Fact]
    public async Task Fields_inside_one_selector_narrow_each_other_rather_than_adding_up()
    {
        await using var db = await SeededAsync();

        // environment + haRole means "the standby in production", not "production plus standbys".
        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - environment: production
                  haRole: standby
            """), default);

        Assert.True(resolution.Ok, string.Join("; ", resolution.Errors));
        Assert.Equal("web-02", Assert.Single(resolution.Targets).Target);
    }

    [Fact]
    public async Task Overlapping_selectors_deploy_each_target_once_and_say_so()
    {
        await using var db = await SeededAsync();

        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - group: web-tier
                  environment: production
                - name: web-01
            """), default);

        Assert.True(resolution.Ok, string.Join("; ", resolution.Errors));
        Assert.Equal(2, resolution.Targets.Count);
        Assert.Equal(resolution.Targets.Count, resolution.Targets.Select(t => t.BindingId).Distinct().Count());
        Assert.Contains(resolution.Warnings, w => w.Contains("overlap"));
    }

    [Fact]
    public async Task A_selector_that_matches_nothing_fails_the_whole_manifest()
    {
        await using var db = await SeededAsync();

        // Deploying to three of the four hosts the file names, silently, is how a server gets
        // left on the old certificate until it expires.
        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - environment: production
                  adapter: nginx
                - name: web-99
            """), default);

        Assert.False(resolution.Ok);
        Assert.Contains(resolution.Errors, e => e.Contains("web-99") && e.Contains("matched no"));
    }

    [Fact]
    public async Task An_ambiguous_common_name_is_refused_instead_of_picking_an_environment()
    {
        await using var db = await SeededAsync();
        // The same name in two environments is normal; guessing between them is not.
        db.Certificates.Add(new Certificate
        {
            Id = Guid.NewGuid(), CommonName = "www.example.com", Environment = "staging"
        });
        await db.SaveChangesAsync();

        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - name: web-01
            """), default);

        Assert.False(resolution.Ok);
        Assert.Contains(resolution.Errors, e => e.Contains("thumbprint"));
    }

    [Fact]
    public async Task A_thumbprint_resolves_whether_or_not_it_is_written_with_colons()
    {
        await using var db = await SeededAsync();
        var thumbprint = new string('A', 64);
        var withColons = string.Join(':', Enumerable.Range(0, 32).Select(_ => "AA"));

        var resolution = await Service(db).ResolveAsync(Manifest($"""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                thumbprint: {withColons}
              targets:
                - name: web-01
            """), default);

        Assert.True(resolution.Ok, string.Join("; ", resolution.Errors));
        Assert.Equal(thumbprint, resolution.Thumbprint);
    }

    [Fact]
    public async Task A_certificate_with_no_active_version_says_how_to_deploy_a_fresh_one()
    {
        await using var db = await SeededAsync();
        var version = await db.CertificateVersions.FirstAsync();
        version.Status = CertificateVersionStatus.Issued;
        await db.SaveChangesAsync();

        var yaml = """
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
                version: {0}
              targets:
                - name: web-01
            """;

        var active = await Service(db).ResolveAsync(Manifest(string.Format(yaml, "active")), default);
        Assert.False(active.Ok);
        Assert.Contains(active.Errors, e => e.Contains("version: latest"));

        // ...and "latest" is exactly what a renewal pipeline needs, so it must find it.
        var latest = await Service(db).ResolveAsync(Manifest(string.Format(yaml, "latest")), default);
        Assert.True(latest.Ok, string.Join("; ", latest.Errors));
        Assert.Equal(version.Id, latest.CertificateVersionId);
    }

    [Fact]
    public async Task The_strategy_defaults_to_sequential_when_the_manifest_stays_silent()
    {
        await using var db = await SeededAsync();

        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - name: web-01
            """), default);

        // The safest strategy is the one you get by not thinking about it.
        Assert.Equal("sequential", resolution.Strategy);
        Assert.False(resolution.ApprovalRequired);
    }

    [Fact]
    public async Task A_dry_run_reports_the_impact_without_creating_anything()
    {
        await using var db = await SeededAsync();

        var (resolution, plan) = await Service(db).PlanAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - environment: production
                  adapter: nginx
              strategy:
                type: wave
                maxConcurrency: 2
            """), default);

        Assert.True(resolution.Ok, string.Join("; ", resolution.Errors));
        Assert.NotNull(plan);
        Assert.Equal("wave", plan!.Strategy);
        Assert.Equal(2, plan.Targets.Count);
        // Read-only: a dry run that queued a job would be worse than no dry run at all.
        Assert.Empty(await db.DeploymentJobs.ToListAsync());
    }
}
