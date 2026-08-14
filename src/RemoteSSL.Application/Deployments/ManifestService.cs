using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Auditing;
using RemoteSSL.Domain;
using RemoteSSL.Domain.Entities;

namespace RemoteSSL.Application.Deployments;

/// <summary>What a manifest resolved to, before anything is changed.</summary>
public sealed record ManifestResolution(
    bool Ok,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    string? Certificate,
    string? Thumbprint,
    Guid? CertificateVersionId,
    string Strategy,
    int MaxConcurrency,
    bool ApprovalRequired,
    IReadOnlyList<ManifestMatchedTarget> Targets);

/// <summary>One binding a selector matched, named the way the manifest names things.</summary>
public sealed record ManifestMatchedTarget(
    Guid BindingId, string Target, string Adapter, string? Environment, string? Group,
    string? HaRole, string Store, int SelectorIndex);

/// <summary>
/// Resolves and applies the declarative manifest of design doc §38.
///
/// Resolution is where the manifest's names become database rows, and it is deliberately the only
/// place that happens: applying then hands the resolved bindings to the same
/// <see cref="DeploymentService"/> the UI uses, so a manifest cannot bypass governance, approval,
/// the adapter allowlist or the §21.1 pipeline. A manifest is a way to describe a deployment, not
/// a second way to perform one.
/// </summary>
public class ManifestService(
    IRemoteSslDbContext db, DeploymentPlanner planner, DeploymentService deployments, AuditWriter audit)
{
    /// <summary>
    /// Turns a validated manifest into the concrete certificate version and bindings it names,
    /// without changing anything. This is what a dry run reports and what apply runs first.
    /// </summary>
    public async Task<ManifestResolution> ResolveAsync(DeploymentManifest manifest, CancellationToken ct)
    {
        var errors = ManifestParser.Validate(manifest).ToList();
        var warnings = new List<string>();
        if (errors.Count > 0) return Failed(errors);

        var spec = manifest.Spec!;

        var version = await ResolveVersionAsync(manifest, errors, ct);
        if (version is null) return Failed(errors);

        // §38 verification.expectedThumbprint: the manifest states what it believes it is
        // deploying. If the file has drifted from the certificate it names, that is a mistake
        // worth stopping for, not something to resolve in the file's favour.
        var expected = spec.Verification?.ExpectedThumbprint?.Replace(":", "").Replace(" ", "").Trim();
        if (!string.IsNullOrWhiteSpace(expected)
            && !expected.Equals(version.Sha256Thumbprint, StringComparison.OrdinalIgnoreCase))
            errors.Add($"spec.verification.expectedThumbprint is {expected}, but the certificate "
                       + $"this manifest resolves to is {version.Sha256Thumbprint}.");

        var matched = await ResolveTargetsAsync(spec, version.CertificateId, errors, warnings, ct);

        var strategy = string.IsNullOrWhiteSpace(spec.Strategy?.Type) ? "sequential" : spec.Strategy!.Type!;
        var concurrency = spec.Strategy?.MaxConcurrency ?? 0;

        return new ManifestResolution(
            errors.Count == 0, errors, warnings,
            version.Certificate.CommonName, version.Sha256Thumbprint, version.Id,
            strategy, concurrency, spec.Approval?.Required ?? false, matched);
    }

    /// <summary>
    /// Dry run: resolves the manifest and produces the same impact preview the UI shows before a
    /// deployment is confirmed (NFR-008), so a manifest can be reviewed in a pull request with the
    /// blast radius attached rather than guessed at.
    /// </summary>
    public async Task<(ManifestResolution Resolution, DeploymentPlan? Plan)> PlanAsync(
        DeploymentManifest manifest, CancellationToken ct)
    {
        var resolution = await ResolveAsync(manifest, ct);
        if (!resolution.Ok) return (resolution, null);

        var plan = await planner.PlanAsync(
            resolution.CertificateVersionId!.Value,
            resolution.Targets.Select(t => t.BindingId).ToList(),
            resolution.Strategy, resolution.MaxConcurrency, resolution.ApprovalRequired, ct);

        return (resolution, plan);
    }

    /// <summary>
    /// Applies the manifest: persists any verification overrides it declares, then creates a
    /// deployment job through the normal orchestrator.
    /// </summary>
    public async Task<(ManifestResolution Resolution, DeploymentJob? Job)> ApplyAsync(
        DeploymentManifest manifest, string requestedBy, CancellationToken ct)
    {
        var resolution = await ResolveAsync(manifest, ct);
        if (!resolution.Ok) return (resolution, null);

        // The manifest is the desired state of the deployment, so its verification block is
        // written onto the bindings before the job runs — otherwise the run would verify against
        // whatever the last UI edit left behind and the file would not describe what happened.
        await ApplyVerificationAsync(manifest.Spec!.Verification, resolution.Targets, ct);

        var job = await deployments.CreateJobAsync(
            resolution.CertificateVersionId!.Value,
            resolution.Targets.Select(t => t.BindingId).ToList(),
            resolution.Strategy, requestedBy, resolution.ApprovalRequired, ct,
            resolution.MaxConcurrency);

        audit.Append(requestedBy, "deployment.manifest.applied", "DeploymentJob", job.Id.ToString(), "success",
            new
            {
                manifest = manifest.Metadata?.Name,
                certificate = resolution.Certificate,
                thumbprint = resolution.Thumbprint,
                strategy = resolution.Strategy,
                targets = resolution.Targets.Select(t => t.Target).ToArray()
            }, job.CorrelationId);
        await db.SaveChangesAsync(ct);

        return (resolution, job);
    }

    private static ManifestResolution Failed(IReadOnlyList<string> errors) =>
        new(false, errors, [], null, null, null, "sequential", 0, false, []);

    /// <summary>
    /// The §38 addressing form. versionId pins an exact version; certificateId alone deploys
    /// whatever is active, so a manifest in git survives a renewal without being edited.
    /// </summary>
    private async Task<CertificateVersion?> ResolveByIdAsync(
        ManifestMetadata metadata, List<string> errors, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(metadata.VersionId))
        {
            var versionId = Guid.Parse(metadata.VersionId);
            var version = await db.CertificateVersions.Include(v => v.Certificate)
                .FirstOrDefaultAsync(v => v.Id == versionId, ct);

            if (version is null)
            {
                errors.Add($"No certificate version with id {versionId} exists.");
                return null;
            }

            // Naming both must agree, or the file means two different things at once.
            if (!string.IsNullOrWhiteSpace(metadata.CertificateId)
                && version.CertificateId != Guid.Parse(metadata.CertificateId))
            {
                errors.Add($"metadata.versionId {versionId} belongs to certificate "
                           + $"{version.CertificateId}, not to metadata.certificateId {metadata.CertificateId}.");
                return null;
            }

            return version;
        }

        var certificateId = Guid.Parse(metadata.CertificateId!);
        var active = await db.CertificateVersions.Include(v => v.Certificate)
            .Where(v => v.CertificateId == certificateId && v.Status == CertificateVersionStatus.Active)
            .OrderByDescending(v => v.NotAfter)
            .FirstOrDefaultAsync(ct);

        if (active is null)
            errors.Add(await db.Certificates.AnyAsync(c => c.Id == certificateId, ct)
                ? $"Certificate {certificateId} has no active version. Pin one with metadata.versionId."
                : $"No certificate with id {certificateId} exists.");

        return active;
    }

    private async Task<CertificateVersion?> ResolveVersionAsync(
        DeploymentManifest manifest, List<string> errors, CancellationToken ct)
    {
        // §38 form: the certificate and (optionally) the exact version are named by id.
        var metadata = manifest.Metadata;
        if (!string.IsNullOrWhiteSpace(metadata?.VersionId) || !string.IsNullOrWhiteSpace(metadata?.CertificateId))
            return await ResolveByIdAsync(metadata!, errors, ct);

        var wanted = manifest.Spec!.Certificate!;

        if (!string.IsNullOrWhiteSpace(wanted.Thumbprint))
        {
            // Operators paste thumbprints from browsers and openssl, which format them differently.
            var normalized = wanted.Thumbprint.Replace(":", "").Replace(" ", "").Trim();
            var byThumbprint = await db.CertificateVersions.Include(v => v.Certificate)
                .FirstOrDefaultAsync(v => v.Sha256Thumbprint == normalized, ct);

            if (byThumbprint is null)
                errors.Add($"No certificate version with thumbprint '{wanted.Thumbprint}' exists.");
            return byThumbprint;
        }

        var name = wanted.CommonName!;
        var certificates = await db.Certificates.Where(c => c.CommonName == name).ToListAsync(ct);

        if (certificates.Count == 0)
        {
            errors.Add($"No certificate with common name '{name}' exists.");
            return null;
        }
        if (certificates.Count > 1)
        {
            // Same name in two environments is normal and the manifest cannot express which one,
            // so refuse rather than pick — deploying to the wrong environment is the worst outcome.
            errors.Add($"'{name}' matches {certificates.Count} certificates "
                       + $"({string.Join(", ", certificates.Select(c => c.Environment ?? "no environment"))}). "
                       + "Use spec.certificate.thumbprint to name one exactly.");
            return null;
        }

        var certificate = certificates[0];
        var wantLatest = string.Equals(wanted.Version, "latest", StringComparison.Ordinal);

        var query = db.CertificateVersions.Include(v => v.Certificate)
            .Where(v => v.CertificateId == certificate.Id);

        var version = wantLatest
            ? await query.Where(v => v.Status == CertificateVersionStatus.Issued
                                     || v.Status == CertificateVersionStatus.Active)
                .OrderByDescending(v => v.NotBefore).FirstOrDefaultAsync(ct)
            : await query.Where(v => v.Status == CertificateVersionStatus.Active)
                .OrderByDescending(v => v.NotAfter).FirstOrDefaultAsync(ct);

        if (version is null)
            errors.Add(wantLatest
                ? $"'{name}' has no issued or active version to deploy."
                : $"'{name}' has no active version. Use version: latest to deploy a freshly issued one.");

        return version;
    }

    private async Task<IReadOnlyList<ManifestMatchedTarget>> ResolveTargetsAsync(
        ManifestSpec spec, Guid certificateId, List<string> errors, List<string> warnings, CancellationToken ct)
    {
        // Only bindings of this certificate are candidates: a manifest names targets, but what is
        // deployed is always a binding of a certificate to a store on that target.
        var candidates = await db.DeploymentBindings
            .Include(b => b.CertificateStore).ThenInclude(s => s.Target)
            .Where(b => b.CertificateId == certificateId)
            .ToListAsync(ct);

        var matched = new Dictionary<Guid, ManifestMatchedTarget>();

        for (var i = 0; i < spec.Targets.Count; i++)
        {
            var selector = spec.Targets[i];
            var hits = candidates.Where(b => Matches(selector, b)).ToList();

            if (hits.Count == 0)
            {
                // A selector that matches nothing is an error, not a warning: silently deploying
                // to fewer targets than the file asks for is how a server gets left behind.
                errors.Add($"spec.targets[{i}] ({Describe(selector)}) matched no deployment binding "
                           + "for this certificate.");
                continue;
            }

            foreach (var b in hits)
            {
                var target = b.CertificateStore.Target;
                if (matched.ContainsKey(b.Id)) continue;
                matched[b.Id] = new ManifestMatchedTarget(
                    b.Id, target.Name, target.AdapterType, target.Environment, target.TargetGroup,
                    target.HaRole, $"{b.CertificateStore.StoreType}:{b.CertificateStore.StorePath}", i);
            }
        }

        // Overlapping selectors are legitimate (a group plus one extra host), but worth saying so
        // the operator knows the target is deployed once, not twice.
        var overlap = spec.Targets.Count > 1
                      && matched.Count < spec.Targets.Sum(s => candidates.Count(b => Matches(s, b)));
        if (overlap)
            warnings.Add("Some selectors overlap; each target is deployed once.");

        return matched.Values.OrderBy(t => t.SelectorIndex).ThenBy(t => t.Target).ToList();
    }

    private static bool Matches(ManifestTargetSelector selector, DeploymentBinding binding)
    {
        var target = binding.CertificateStore.Target;
        var store = binding.CertificateStore;

        // Fields within one selector are AND-ed; an unset field simply does not constrain.
        if (!Eq(selector.TargetName, target.Name)) return false;
        if (!Eq(selector.Environment, target.Environment)) return false;
        if (!Eq(selector.Adapter, target.AdapterType)) return false;
        if (!Eq(selector.Group, target.TargetGroup)) return false;
        if (!Eq(selector.HaRole, target.HaRole)) return false;

        // §38 store/alias: a target can carry several stores (two keystores, My and Root), so
        // these are what pick one. Without them a manifest naming the target alone would deploy
        // to all of them.
        if (!Eq(selector.Alias, store.Alias)) return false;
        if (!string.IsNullOrWhiteSpace(selector.Store)
            && !StoreMatches(selector.Store, store)) return false;

        // §38 service: the service the binding activates, e.g. nginx.
        if (!string.IsNullOrWhiteSpace(selector.Service)
            && !ServiceMatches(selector.Service, binding.ServiceBindingJson)) return false;

        return true;

        static bool Eq(string? wanted, string? actual) =>
            string.IsNullOrWhiteSpace(wanted)
            || string.Equals(wanted, actual, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Matches the store the way an operator writes it: the bare path as in §38
    /// (<c>/etc/nginx/ssl</c>, <c>LocalMachine/My</c>) or the qualified <c>type:path</c> form the
    /// UI shows. Windows store paths are written with either slash.
    /// </summary>
    private static bool StoreMatches(string wanted, CertificateStore store)
    {
        var candidates = new[] { store.StorePath, $"{store.StoreType}:{store.StorePath}" };
        return candidates.Any(c => Normalize(c) == Normalize(wanted));

        static string Normalize(string value) =>
            value.Trim().TrimEnd('/', '\\').Replace('\\', '/').ToLowerInvariant();
    }

    private static bool ServiceMatches(string wanted, string serviceBindingJson)
    {
        try
        {
            if (JsonNode.Parse(string.IsNullOrWhiteSpace(serviceBindingJson) ? "{}" : serviceBindingJson)
                is not JsonObject config) return false;

            return config["service"]?.GetValue<string>() is { } service
                   && string.Equals(service, wanted, StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException) { return false; }
    }

    private static string Describe(ManifestTargetSelector selector)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(selector.TargetName)) parts.Add($"target={selector.TargetName}");
        if (!string.IsNullOrWhiteSpace(selector.Environment)) parts.Add($"environment={selector.Environment}");
        if (!string.IsNullOrWhiteSpace(selector.Adapter)) parts.Add($"adapter={selector.Adapter}");
        if (!string.IsNullOrWhiteSpace(selector.Store)) parts.Add($"store={selector.Store}");
        if (!string.IsNullOrWhiteSpace(selector.Alias)) parts.Add($"alias={selector.Alias}");
        if (!string.IsNullOrWhiteSpace(selector.Service)) parts.Add($"service={selector.Service}");
        if (!string.IsNullOrWhiteSpace(selector.Group)) parts.Add($"group={selector.Group}");
        if (!string.IsNullOrWhiteSpace(selector.HaRole)) parts.Add($"haRole={selector.HaRole}");
        return string.Join(", ", parts);
    }

    /// <summary>
    /// Writes the manifest's verification block onto the matched bindings. Only the keys the
    /// manifest actually declares are touched, so an unrelated setting an operator put on the
    /// binding survives a manifest that says nothing about it.
    /// </summary>
    private async Task ApplyVerificationAsync(
        ManifestVerification? verification, IReadOnlyList<ManifestMatchedTarget> targets, CancellationToken ct)
    {
        if (verification is null) return;

        var ids = targets.Select(t => t.BindingId).ToList();
        var bindings = await db.DeploymentBindings.Where(b => ids.Contains(b.Id)).ToListAsync(ct);

        foreach (var binding in bindings)
        {
            var config = ParseObject(binding.ServiceBindingJson);

            if (!string.IsNullOrWhiteSpace(verification.Host)) config["verifyHost"] = verification.Host;
            if (verification.Port is { } port) config["verifyPort"] = port;
            if (!string.IsNullOrWhiteSpace(verification.Sni)) config["verifySni"] = verification.Sni;

            // remoteTlsVerify: false clears the override so the run falls back to the monitor
            // endpoint, which is the documented best-effort behaviour rather than "skip".
            if (verification.RemoteTlsVerify is false)
            {
                config.Remove("verifyHost");
                config.Remove("verifyPort");
                config.Remove("verifySni");
            }

            binding.ServiceBindingJson = config.ToJsonString();
        }

        await db.SaveChangesAsync(ct);
    }

    private static JsonObject ParseObject(string json)
    {
        try
        {
            return JsonNode.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json) as JsonObject ?? new JsonObject();
        }
        catch (JsonException)
        {
            return new JsonObject();
        }
    }
}
