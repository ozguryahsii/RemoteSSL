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

    /// <summary>
    /// The manifest exactly as design doc §38 prints it. If this stops parsing, the product has
    /// drifted from the document, which is the one thing the manifest format must not do.
    /// </summary>
    public const string DocumentExample = """
        apiVersion: remotessl/v1
        kind: CertificateDeployment
        metadata:
          certificateId: 11111111-1111-1111-1111-111111111111
          versionId: 22222222-2222-2222-2222-222222222222
        spec:
          strategy:
            type: wave
            maxConcurrency: 2
          verification:
            expectedThumbprint: ABCDEF
            rollbackOnFailure: true
          targets:
            - target: web01
              adapter: nginx
              store: /etc/nginx/ssl
              service: nginx
            - target: wexch01
              adapter: windows-cert-store
              store: LocalMachine/My
            - target: wls01
              adapter: java-truststore
              store: /opt/app/truststore.jks
              alias: globalsign-r46
        """;

    [Fact]
    public void The_example_manifest_printed_in_the_design_document_parses_field_for_field()
    {
        var result = ManifestParser.Parse(DocumentExample);

        Assert.True(result.Ok, string.Join("; ", result.Errors));
        var manifest = result.Manifest!;
        Assert.Equal("11111111-1111-1111-1111-111111111111", manifest.Metadata!.CertificateId);
        Assert.Equal("22222222-2222-2222-2222-222222222222", manifest.Metadata.VersionId);

        var spec = manifest.Spec!;
        Assert.Equal("wave", spec.Strategy!.Type);
        Assert.Equal(2, spec.Strategy.MaxConcurrency);
        Assert.Equal("ABCDEF", spec.Verification!.ExpectedThumbprint);
        Assert.True(spec.Verification.RollbackOnFailure);

        Assert.Equal(3, spec.Targets.Count);
        Assert.Equal("web01", spec.Targets[0].Target);
        Assert.Equal("nginx", spec.Targets[0].Adapter);
        Assert.Equal("/etc/nginx/ssl", spec.Targets[0].Store);
        Assert.Equal("nginx", spec.Targets[0].Service);
        Assert.Equal("LocalMachine/My", spec.Targets[1].Store);
        Assert.Equal("globalsign-r46", spec.Targets[2].Alias);
    }

    [Fact]
    public void Turning_rollback_off_is_refused_rather_than_accepted_and_ignored()
    {
        // A file that says rollback is off, applied to a pipeline that always rolls back, would
        // mislead whoever reads it during an incident.
        var result = ManifestParser.Parse(DocumentExample.Replace(
            "rollbackOnFailure: true", "rollbackOnFailure: false"));

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("rollbackOnFailure"));
    }

    [Fact]
    public void Naming_the_certificate_in_both_places_at_once_is_refused()
    {
        var result = ManifestParser.Parse("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            metadata:
              certificateId: 11111111-1111-1111-1111-111111111111
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - target: web01
            """);

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("named twice"));
    }

    [Fact]
    public void An_id_that_is_not_a_remotessl_id_is_reported_as_such()
    {
        var result = ManifestParser.Parse("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            metadata:
              certificateId: cert-123
            spec:
              targets:
                - target: web01
            """);

        Assert.False(result.Ok);
        Assert.Contains(result.Errors, e => e.Contains("metadata.certificateId"));
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
    public async Task A_certificate_addressed_by_id_resolves_to_its_active_version()
    {
        await using var db = await SeededAsync();
        var certificate = await db.Certificates.FirstAsync();
        var active = await db.CertificateVersions.FirstAsync();

        var resolution = await Service(db).ResolveAsync(Manifest($"""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            metadata:
              certificateId: {certificate.Id}
            spec:
              targets:
                - target: web-01
            """), default);

        Assert.True(resolution.Ok, string.Join("; ", resolution.Errors));
        Assert.Equal(active.Id, resolution.CertificateVersionId);
    }

    [Fact]
    public async Task A_version_id_that_belongs_to_another_certificate_is_refused()
    {
        await using var db = await SeededAsync();
        var version = await db.CertificateVersions.FirstAsync();
        var other = Guid.NewGuid();

        var resolution = await Service(db).ResolveAsync(Manifest($"""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            metadata:
              certificateId: {other}
              versionId: {version.Id}
            spec:
              targets:
                - target: web-01
            """), default);

        Assert.False(resolution.Ok);
        Assert.Contains(resolution.Errors, e => e.Contains("belongs to certificate"));
    }

    [Fact]
    public async Task The_store_path_picks_one_of_several_stores_on_the_same_target()
    {
        await using var db = await SeededAsync();

        // A second store on web-01: naming the target alone would now be ambiguous, which is
        // exactly why §38 puts the store path in the selector.
        var target = await db.Targets.FirstAsync(t => t.Name == "web-01");
        var certificate = await db.Certificates.FirstAsync();
        var second = new CertificateStore
        {
            Id = Guid.NewGuid(), TargetId = target.Id, Target = target,
            StoreType = "pem-file", StorePath = "/etc/ssl/secondary.pem"
        };
        db.CertificateStores.Add(second);
        db.DeploymentBindings.Add(new DeploymentBinding
        {
            Id = Guid.NewGuid(), CertificateId = certificate.Id, Certificate = certificate,
            CertificateStoreId = second.Id, CertificateStore = second
        });
        await db.SaveChangesAsync();

        var both = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - target: web-01
            """), default);
        Assert.Equal(2, both.Targets.Count);

        var narrowed = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              targets:
                - target: web-01
                  store: /etc/ssl/secondary.pem
            """), default);

        Assert.True(narrowed.Ok, string.Join("; ", narrowed.Errors));
        Assert.Equal("pem-file:/etc/ssl/secondary.pem", Assert.Single(narrowed.Targets).Store);
    }

    [Fact]
    public async Task An_expected_thumbprint_that_no_longer_matches_stops_the_manifest()
    {
        await using var db = await SeededAsync();

        // The file states what it believes it is deploying; if it has drifted from the
        // certificate it names, that is a mistake worth stopping for.
        var resolution = await Service(db).ResolveAsync(Manifest("""
            apiVersion: remotessl/v1
            kind: CertificateDeployment
            spec:
              certificate:
                commonName: www.example.com
              verification:
                expectedThumbprint: DEADBEEF
              targets:
                - target: web-01
            """), default);

        Assert.False(resolution.Ok);
        Assert.Contains(resolution.Errors, e => e.Contains("expectedThumbprint"));
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
