namespace RemoteSSL.Domain.Abstractions;

/// <summary>
/// Capabilities an adapter may advertise. The UI is capability-driven: actions are
/// only offered when the adapter declares support for them.
/// </summary>
public enum AdapterCapability
{
    Discover,
    GenerateCsrOnTarget,
    Backup,
    Install,
    Activate,
    Validate,
    Reload,
    Rollback
}

/// <summary>
/// The contract every certificate store adapter (nginx, IIS, JKS, Oracle wallet,
/// F5 …) implements. Adapters run on the runner, receive a resolved execution
/// context and must be idempotent per step: re-delivering the same step must not
/// produce a duplicate deployment.
/// </summary>
public interface ICertificateTargetAdapter
{
    /// <summary>Stable adapter identifier, e.g. "nginx", "windows-cert-store".</summary>
    string AdapterType { get; }

    IReadOnlyCollection<AdapterCapability> Capabilities { get; }

    Task<AdapterResult> TestConnectionAsync(TargetContext ctx, CancellationToken ct);
    Task<AdapterResult> DiscoverAsync(TargetContext ctx, CancellationToken ct);
    Task<AdapterResult> GenerateCsrAsync(TargetContext ctx, CsrRequest request, CancellationToken ct);
    Task<AdapterResult> BackupAsync(DeploymentContext ctx, CancellationToken ct);
    Task<AdapterResult> InstallAsync(DeploymentContext ctx, CancellationToken ct);
    Task<AdapterResult> ActivateAsync(DeploymentContext ctx, CancellationToken ct);
    Task<AdapterResult> ValidateAsync(DeploymentContext ctx, CancellationToken ct);
    Task<AdapterResult> ReloadAsync(DeploymentContext ctx, CancellationToken ct);
    Task<AdapterResult> RollbackAsync(DeploymentContext ctx, CancellationToken ct);
    Task<AdapterResult> CleanupAsync(DeploymentContext ctx, CancellationToken ct);
}

/// <summary>Connection info for one target; secrets arrive as resolved references, never persisted.</summary>
public sealed record TargetContext(
    Guid TargetId,
    string AdapterType,
    string ConnectionConfigJson,
    string? StorePath,
    string? Alias);

public sealed record CsrRequest(
    string SubjectDn,
    IReadOnlyList<string> SubjectAlternativeNames,
    string KeyAlgorithm,
    int KeySizeOrCurve);

public sealed record DeploymentContext(
    Guid JobId,
    Guid JobTargetId,
    TargetContext Target,
    string? ExpectedSha256Thumbprint,
    string IdempotencyKey);

/// <summary>
/// Uniform step result. SafeLog must contain sanitized metadata only (hashes, paths,
/// operations) — never secrets, private keys or raw sensitive command output.
/// </summary>
public sealed record AdapterResult(
    bool Success,
    string? SafeLog = null,
    string? ErrorCode = null,
    bool RetrySafe = false);
