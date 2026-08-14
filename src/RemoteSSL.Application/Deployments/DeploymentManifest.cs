using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace RemoteSSL.Application.Deployments;

/// <summary>
/// The declarative deployment manifest of design doc §38.
///
/// The point of the manifest is that a deployment can live in the same git repository as the
/// service it renews: reviewed, diffed and applied like any other configuration. It therefore
/// names things the way an operator does — a certificate by its common name, targets by
/// environment or group — and never by database id, which would make the file unreadable and
/// unportable between environments.
///
/// Applying a manifest goes through exactly the same planner and orchestrator as the UI, so
/// governance, approval, adapter allowlisting and the §21.1 pipeline all apply unchanged. The
/// manifest is an input format, not a second way to deploy.
/// </summary>
public sealed class DeploymentManifest
{
    public const string SupportedApiVersion = "remotessl/v1";
    public const string SupportedKind = "CertificateDeployment";

    public string? ApiVersion { get; set; }
    public string? Kind { get; set; }
    public ManifestMetadata? Metadata { get; set; }
    public ManifestSpec? Spec { get; set; }
}

public sealed class ManifestMetadata
{
    /// <summary>
    /// The certificate to deploy, as the §38 example names it. Accepts a RemoteSSL id (GUID) so a
    /// manifest generated from the API round-trips exactly.
    /// </summary>
    public string? CertificateId { get; set; }

    /// <summary>
    /// The specific version to deploy (§38). When omitted the active version is used, so a
    /// manifest kept in git does not have to be edited on every renewal.
    /// </summary>
    public string? VersionId { get; set; }

    /// <summary>Free-text name for the deployment; carried into the job as the requester note.</summary>
    public string? Name { get; set; }
    public string? Description { get; set; }
}

public sealed class ManifestSpec
{
    public ManifestCertificate? Certificate { get; set; }

    /// <summary>
    /// Target selectors, OR-ed together: a target matches the spec if it matches any one of them.
    /// An empty list is rejected rather than treated as "everything" — a manifest that silently
    /// selected every target in the estate is the most expensive possible typo.
    /// </summary>
    public List<ManifestTargetSelector> Targets { get; set; } = [];

    public ManifestStrategy? Strategy { get; set; }
    public ManifestVerification? Verification { get; set; }
    public ManifestApproval? Approval { get; set; }
}

/// <summary>Which certificate to deploy. Exactly one identifying field must be given.</summary>
public sealed class ManifestCertificate
{
    public string? CommonName { get; set; }
    /// <summary>SHA-256 thumbprint of a specific version, with or without colons.</summary>
    public string? Thumbprint { get; set; }

    /// <summary>
    /// Which version of that certificate: "active" (default) or "latest". "latest" picks the
    /// newest issued version even if it has not been activated yet, which is what a renewal
    /// pipeline wants; "active" is what a re-deployment of the current state wants.
    /// </summary>
    public string? Version { get; set; }
}

/// <summary>
/// One selector. Fields within a selector are AND-ed: <c>environment: production</c> plus
/// <c>adapter: nginx</c> means production nginx targets, not their union.
/// </summary>
public sealed class ManifestTargetSelector
{
    /// <summary>Exact target name, spelled as the §38 example spells it.</summary>
    public string? Target { get; set; }

    /// <summary>Alias for <see cref="Target"/>, so both spellings read naturally in a file.</summary>
    public string? Name { get; set; }

    public string? Environment { get; set; }
    public string? Adapter { get; set; }

    /// <summary>
    /// Store path on the target (§38: <c>/etc/nginx/ssl</c>, <c>LocalMachine/My</c>,
    /// <c>/opt/app/truststore.jks</c>). A target can carry several stores, so this is what picks
    /// one of them — without it a target with two keystores would be ambiguous.
    /// </summary>
    public string? Store { get; set; }

    /// <summary>Keystore alias (§38: <c>globalsign-r46</c>); narrows further within a store.</summary>
    public string? Alias { get; set; }

    /// <summary>Service the binding activates (§38: <c>nginx</c>).</summary>
    public string? Service { get; set; }

    public string? Group { get; set; }
    /// <summary>"standby" | "active" — restricts to one side of an HA pair.</summary>
    public string? HaRole { get; set; }

    /// <summary>The target name however it was spelled.</summary>
    public string? TargetName => string.IsNullOrWhiteSpace(Target) ? Name : Target;
}

public sealed class ManifestStrategy
{
    /// <summary>sequential | parallel | wave | canary | manual | ha-pair | all-at-once (§21.4).</summary>
    public string? Type { get; set; }
    public int? MaxConcurrency { get; set; }
}

/// <summary>
/// Post-deployment verification (§21.1). These map onto the binding's verify settings, so a
/// manifest can point the remote check at the load balancer name that actually serves traffic
/// rather than at the host the file was written to.
/// </summary>
public sealed class ManifestVerification
{
    /// <summary>
    /// The thumbprint the manifest expects to deploy (§38). Asserted against the version that was
    /// actually resolved: a file that has drifted from the certificate it names is refused rather
    /// than quietly deploying something else.
    /// </summary>
    public string? ExpectedThumbprint { get; set; }

    /// <summary>
    /// §38. Automatic rollback is a property of the pipeline (§21.1), so only <c>true</c> is
    /// accepted; <c>false</c> is refused explicitly rather than silently ignored.
    /// </summary>
    public bool? RollbackOnFailure { get; set; }

    /// <summary>Probe the endpoint after activation and require the new thumbprint. Default true.</summary>
    public bool? RemoteTlsVerify { get; set; }
    public string? Host { get; set; }
    public int? Port { get; set; }
    public string? Sni { get; set; }
}

public sealed class ManifestApproval
{
    /// <summary>
    /// Ask for approval even where policy would not. Policy may still raise the bar: a manifest
    /// can request approval, never waive it.
    /// </summary>
    public bool? Required { get; set; }
}

/// <summary>
/// Parses and validates manifest documents. Parsing and validation are deliberately separate
/// from resolution: a malformed file should be reported as a malformed file, with the YAML line
/// it failed on, rather than as "certificate not found" three steps later.
/// </summary>
public static class ManifestParser
{
    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        // Manifests are written by hand, so accept camelCase as documented and ignore nothing
        // silently: an unknown key is far more likely to be a typo in a key that matters
        // (maxConcurrency vs maxConcurrancy) than a deliberate annotation.
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    public sealed record ParseResult(DeploymentManifest? Manifest, IReadOnlyList<string> Errors)
    {
        public bool Ok => Manifest is not null && Errors.Count == 0;
    }

    /// <summary>
    /// Reads a YAML (or JSON — YAML is a superset) manifest and validates its shape. Returns every
    /// problem found rather than the first, so an operator fixes the file in one pass.
    /// </summary>
    public static ParseResult Parse(string document)
    {
        if (string.IsNullOrWhiteSpace(document))
            return new ParseResult(null, ["The manifest is empty."]);

        DeploymentManifest? manifest;
        try
        {
            manifest = Yaml.Deserialize<DeploymentManifest>(document);
        }
        catch (YamlException ex)
        {
            // The line number is the most useful thing we can hand back for a hand-written file.
            return new ParseResult(null,
                [$"Line {ex.Start.Line}, column {ex.Start.Column}: {ex.InnerException?.Message ?? ex.Message}"]);
        }
        catch (Exception ex)
        {
            return new ParseResult(null, [$"The manifest could not be read: {ex.Message}"]);
        }

        if (manifest is null)
            return new ParseResult(null, ["The manifest is empty."]);

        return new ParseResult(manifest, Validate(manifest));
    }

    public static IReadOnlyList<string> Validate(DeploymentManifest manifest)
    {
        var errors = new List<string>();

        if (!string.Equals(manifest.ApiVersion, DeploymentManifest.SupportedApiVersion, StringComparison.Ordinal))
            errors.Add($"apiVersion must be '{DeploymentManifest.SupportedApiVersion}' "
                       + $"(found '{manifest.ApiVersion ?? "nothing"}').");

        if (!string.Equals(manifest.Kind, DeploymentManifest.SupportedKind, StringComparison.Ordinal))
            errors.Add($"kind must be '{DeploymentManifest.SupportedKind}' (found '{manifest.Kind ?? "nothing"}').");

        var spec = manifest.Spec;
        if (spec is null)
        {
            errors.Add("spec is required.");
            return errors;
        }

        // The certificate can be named two ways: metadata.certificateId/versionId as in the §38
        // example, or spec.certificate by common name/thumbprint for a file that should keep
        // working across renewals. Exactly one route, so a manifest can never name two.
        var certificate = spec.Certificate;
        var byMetadata = !string.IsNullOrWhiteSpace(manifest.Metadata?.CertificateId)
                         || !string.IsNullOrWhiteSpace(manifest.Metadata?.VersionId);
        var bySpec = certificate is not null
                     && (!string.IsNullOrWhiteSpace(certificate.CommonName)
                         || !string.IsNullOrWhiteSpace(certificate.Thumbprint));

        if (!byMetadata && !bySpec)
            errors.Add("The certificate is not named: give metadata.certificateId (with optional "
                       + "versionId), or spec.certificate with commonName or thumbprint.");

        if (byMetadata && bySpec)
            errors.Add("The certificate is named twice, in metadata and in spec.certificate; "
                       + "give exactly one.");

        if (byMetadata)
        {
            foreach (var (field, value) in new[]
                     {
                         ("metadata.certificateId", manifest.Metadata!.CertificateId),
                         ("metadata.versionId", manifest.Metadata!.VersionId)
                     })
            {
                if (!string.IsNullOrWhiteSpace(value) && !Guid.TryParse(value, out _))
                    errors.Add($"{field} must be a RemoteSSL id (found '{value}').");
            }
        }

        if (certificate is not null)
        {
            if (!string.IsNullOrWhiteSpace(certificate.CommonName)
                && !string.IsNullOrWhiteSpace(certificate.Thumbprint))
                errors.Add("spec.certificate has both commonName and thumbprint; give exactly one.");

            if (certificate.Version is { } version && !string.IsNullOrWhiteSpace(version)
                && version is not ("active" or "latest"))
                errors.Add($"spec.certificate.version must be 'active' or 'latest' (found '{version}').");
        }

        // An empty selector list would mean "every target", which is never what someone meant to
        // write, and an empty selector object inside the list means the same thing one level down.
        if (spec.Targets.Count == 0)
            errors.Add("spec.targets must select at least one target.");

        for (var i = 0; i < spec.Targets.Count; i++)
        {
            var selector = spec.Targets[i];
            var hasCriteria = new[]
            {
                selector.TargetName, selector.Environment, selector.Adapter, selector.Store,
                selector.Alias, selector.Service, selector.Group, selector.HaRole
            }.Any(v => !string.IsNullOrWhiteSpace(v));

            if (!hasCriteria)
                errors.Add($"spec.targets[{i}] is empty; a selector with no criteria would match every target.");

            if (!string.IsNullOrWhiteSpace(selector.Target) && !string.IsNullOrWhiteSpace(selector.Name)
                && !string.Equals(selector.Target, selector.Name, StringComparison.OrdinalIgnoreCase))
                errors.Add($"spec.targets[{i}] gives both target and name, and they disagree.");

            if (!string.IsNullOrWhiteSpace(selector.HaRole)
                && selector.HaRole is not ("standby" or "active"))
                errors.Add($"spec.targets[{i}].haRole must be 'standby' or 'active' (found '{selector.HaRole}').");
        }

        if (spec.Strategy?.Type is { } strategy && !string.IsNullOrWhiteSpace(strategy)
            && !KnownStrategies.Contains(strategy))
            errors.Add($"spec.strategy.type '{strategy}' is not a known strategy "
                       + $"({string.Join(", ", KnownStrategies)}).");

        if (spec.Strategy?.MaxConcurrency is { } concurrency && concurrency < 0)
            errors.Add("spec.strategy.maxConcurrency cannot be negative.");

        if (spec.Verification?.Port is { } port && port is < 1 or > 65535)
            errors.Add($"spec.verification.port must be between 1 and 65535 (found {port}).");

        // Refusing this is safer than accepting a flag that does nothing: a file that says
        // rollback is off, applied to a pipeline that always rolls back, would mislead whoever
        // reads it during an incident.
        if (spec.Verification?.RollbackOnFailure is false)
            errors.Add("spec.verification.rollbackOnFailure cannot be false: automatic rollback is "
                       + "part of the deployment pipeline and cannot be turned off per manifest.");

        return errors;
    }

    /// <summary>The §21.4 strategies the orchestrator implements, as accepted in a manifest.</summary>
    public static readonly IReadOnlySet<string> KnownStrategies = new HashSet<string>(StringComparer.Ordinal)
    {
        "sequential", "parallel", "wave", "canary", "manual", "ha-pair", "all-at-once"
    };
}
