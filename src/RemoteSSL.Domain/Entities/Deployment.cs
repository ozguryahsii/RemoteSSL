namespace RemoteSSL.Domain.Entities;

/// <summary>
/// One operation applying a certificate version to one or more targets, executed as a
/// transactional pipeline (pre-check → backup → install → validate → activate →
/// verify → commit, with rollback on failure).
/// </summary>
public class DeploymentJob
{
    public Guid Id { get; set; }
    public Guid CertificateVersionId { get; set; }
    public CertificateVersion CertificateVersion { get; set; } = null!;
    public DeploymentJobStatus Status { get; set; }

    /// <summary>Deployment strategy: "all-at-once", "sequential", "parallel", "wave" (design doc §21.4).</summary>
    public string Strategy { get; set; } = "sequential";
    /// <summary>Max targets dispatched concurrently (wave/parallel). 0 = all-at-once.</summary>
    public int MaxConcurrency { get; set; } = 1;
    /// <summary>Stop dispatching further waves after any target fails (fail-fast).</summary>
    public bool StopOnFailure { get; set; } = true;
    public string? RequestedBy { get; set; }
    public string? ApprovedBy { get; set; }
    public string CorrelationId { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }

    public ICollection<DeploymentJobTarget> Targets { get; set; } = new List<DeploymentJobTarget>();
}

public class DeploymentJobTarget
{
    public Guid Id { get; set; }
    public Guid DeploymentJobId { get; set; }
    public DeploymentJob DeploymentJob { get; set; } = null!;
    public Guid DeploymentBindingId { get; set; }
    public DeploymentBinding DeploymentBinding { get; set; } = null!;

    public DeploymentJobStatus Status { get; set; }
    /// <summary>Version active before this job, for rollback bookkeeping.</summary>
    public Guid? PreviousVersionId { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }

    public ICollection<DeploymentStep> Steps { get; set; } = new List<DeploymentStep>();
}

/// <summary>
/// An atomic, idempotent step of a deployment. SafeLog contains sanitized metadata
/// only — never secrets, key material or raw command output with sensitive content.
/// </summary>
public class DeploymentStep
{
    public Guid Id { get; set; }
    public Guid DeploymentJobTargetId { get; set; }
    public DeploymentJobTarget DeploymentJobTarget { get; set; } = null!;

    public DeploymentStepType StepType { get; set; }
    public StepStatus Status { get; set; }
    public int RetryCount { get; set; }
    public string IdempotencyKey { get; set; } = string.Empty;
    public string? SafeLog { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
}
