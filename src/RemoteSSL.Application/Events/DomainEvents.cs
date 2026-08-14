namespace RemoteSSL.Application.Events;

/// <summary>
/// The domain event vocabulary of design doc §28.1. Every event the platform publishes is named
/// here, so consumers bind to a known set rather than to whatever string a call site happened to
/// pass. Names are dotted and stable — they are the routing keys on the RabbitMQ topic exchange
/// and the discriminator every integration switches on.
/// </summary>
public static class DomainEvents
{
    /// <summary>Schema version carried in every envelope; bump only on a breaking payload change.</summary>
    public const int SchemaVersion = 1;

    // Discovery and inventory
    public const string CertificateDiscovered = "certificate.discovered";
    public const string CertificateExpiring = "certificate.expiring";
    public const string CertificateExpired = "certificate.expired";
    public const string CertificateRevoked = "certificate.revoked";
    public const string RenewalDue = "certificate.renewal-due";

    // Requests and issuance
    public const string RequestSubmitted = "request.submitted";
    public const string RequestApproved = "request.approved";
    public const string RequestRejected = "request.rejected";
    public const string CertificateIssued = "certificate.issued";
    public const string IssuanceFailed = "certificate.issuance-failed";

    // Deployment
    public const string DeploymentRequested = "deployment.requested";
    public const string DeploymentApproved = "deployment.approved";
    public const string DeploymentStarted = "deployment.started";
    public const string DeploymentAwaitingContinue = "deployment.awaiting-continue";
    public const string DeploymentCompleted = "deployment.completed";
    public const string DeploymentFailed = "deployment.failed";
    public const string RollbackStarted = "deployment.rollback-started";
    public const string RollbackCompleted = "deployment.rollback-completed";

    // Monitoring
    public const string MonitorHealthCheckFailed = "monitor.health-check-failed";
    public const string VantageMismatch = "vantage.mismatch";
    public const string DriftDetected = "drift.detected";

    // Runners and platform
    public const string RunnerRegistered = "runner.registered";
    public const string RunnerOffline = "runner.offline";
    public const string RunnerOnline = "runner.online";
    public const string CredentialRotationDue = "credential.rotation_due";
    public const string NotificationDeliveryFailed = "notification.delivery-failed";

    /// <summary>
    /// Events serious enough to page someone (§33). Everything else goes to chat and the SIEM,
    /// which is the difference between "someone should know" and "wake someone up".
    /// </summary>
    public static readonly IReadOnlySet<string> Incidents = new HashSet<string>
    {
        DeploymentFailed, RollbackStarted, IssuanceFailed, CertificateExpired,
        DriftDetected, RunnerOffline, NotificationDeliveryFailed
    };

    /// <summary>Events that warrant a change/ticket record in the ITSM system (§33).</summary>
    public static readonly IReadOnlySet<string> ChangeWorthy = new HashSet<string>
    {
        DeploymentRequested, DeploymentApproved, DeploymentCompleted,
        DeploymentFailed, RollbackStarted, CertificateRevoked
    };

    /// <summary>
    /// True for the <c>audit.*</c> mirror events of §25.3. They exist for the SIEM and the message
    /// bus; sending every audit row to a chat channel would drown the events that need a human.
    /// </summary>
    public static bool IsAuditMirror(string eventType) =>
        eventType.StartsWith("audit.", StringComparison.Ordinal);

    /// <summary>
    /// Syslog severity per RFC 5424 for an event; used by the SIEM forwarder so an operator can
    /// filter on severity without knowing RemoteSSL's event names.
    /// </summary>
    public static int SeverityOf(string eventType) => eventType switch
    {
        DeploymentFailed or IssuanceFailed or CertificateExpired or RunnerOffline => 3, // error
        RollbackStarted or DriftDetected or VantageMismatch or MonitorHealthCheckFailed
            or CertificateExpiring or RenewalDue or CredentialRotationDue
            or NotificationDeliveryFailed or RequestRejected => 4,                      // warning
        _ => 6                                                                          // informational
    };
}
