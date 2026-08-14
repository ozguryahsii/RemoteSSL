namespace RemoteSSL.Domain.Entities;

/// <summary>
/// A credential-less TLS probe target: host/IP + port + optional SNI. Monitoring an
/// endpoint never requires credentials; adding credentials to the underlying system
/// happens on a separate <see cref="Target"/> entity, not here.
/// </summary>
public class MonitorEndpoint : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35); every query is filtered to it. Left empty on construction
    /// and stamped at save time from the tenant in force, so a row cannot be created under the
    /// wrong tenant by forgetting to set it.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid Id { get; set; }
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 443;
    public string? Sni { get; set; }
    public bool Enabled { get; set; } = true;

    /// <summary>Probe interval in minutes; policy default applies when null.</summary>
    public int? ProbeIntervalMinutes { get; set; }

    // --- Probe policy (design doc §5.2 monitor_endpoint.probe_policy) ---
    /// <summary>Handshake protocol: "tls" (direct) — recorded so future STARTTLS flavours fit.</summary>
    public string Protocol { get; set; } = "tls";
    /// <summary>Connect + handshake timeout; the service default applies when null.</summary>
    public int? TimeoutSeconds { get; set; }
    /// <summary>Extra attempts before a probe is called failed; 0 = single attempt.</summary>
    public int RetryCount { get; set; }

    // --- Optional application reachability check (§2.1) ---
    /// <summary>HTTP(S) URL probed after the TLS handshake; null = TLS only.</summary>
    public string? HealthCheckUrl { get; set; }
    /// <summary>Status code that counts as healthy; null = any 2xx/3xx.</summary>
    public int? HealthCheckExpectedStatus { get; set; }
    /// <summary>"NotConfigured" | "Healthy" | "Unhealthy" | "Unreachable".</summary>
    public string HealthCheckStatus { get; set; } = "NotConfigured";
    public string? HealthCheckDetail { get; set; }
    public DateTimeOffset? HealthCheckAt { get; set; }
    public int? HealthCheckLatencyMs { get; set; }

    /// <summary>
    /// Internal vantage: when set, this runner (living next to the application)
    /// probes the endpoint in addition to the control plane. Comparing both answers
    /// reveals a layer where the certificate was replaced externally but not
    /// internally (or vice versa).
    /// </summary>
    public Guid? RunnerId { get; set; }

    /// <summary>External vantage (control plane). Disable for endpoints that are internal-only.</summary>
    public bool ExternalProbeEnabled { get; set; } = true;

    // --- Internal vantage observation (mirrors the external fields above) ---
    public ProbeStatus InternalProbeStatus { get; set; }
    public string? InternalProbeError { get; set; }
    public DateTimeOffset? InternalProbeAt { get; set; }
    public Guid? InternalObservedVersionId { get; set; }
    public CertificateVersion? InternalObservedVersion { get; set; }
    public bool? InternalHostnameValid { get; set; }
    public bool? InternalChainValid { get; set; }
    public string? InternalChainError { get; set; }
    public string? InternalTlsProtocol { get; set; }
    /// <summary>Negotiated cipher suite from the inside (§6.2 security posture).</summary>
    public string? InternalCipherSuite { get; set; }

    public ProbeStatus LastProbeStatus { get; set; }
    public string? LastProbeError { get; set; }
    public DateTimeOffset? LastProbeAt { get; set; }
    public Guid? LastObservedVersionId { get; set; }
    public CertificateVersion? LastObservedVersion { get; set; }

    public bool? LastHostnameValid { get; set; }
    public bool? LastChainValid { get; set; }
    public string? LastChainError { get; set; }
    public string? LastTlsProtocol { get; set; }
    /// <summary>Negotiated cipher suite, alongside the TLS version (§6.2 security posture).</summary>
    public string? LastCipherSuite { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<MonitorCertificateLink> CertificateLinks { get; set; } = new List<MonitorCertificateLink>();
}

/// <summary>
/// Many-to-many correlation between monitors and logical certificates. The same
/// certificate observed on several endpoints yields one Certificate and N links.
/// </summary>
public class MonitorCertificateLink : ITenantScoped
{
    /// <summary>
    /// Owning tenant (design doc §35). Carried on the child as well as the parent: a query that
    /// starts at the child would otherwise cross the tenant boundary the parent's filter draws.
    /// </summary>
    public Guid TenantId { get; set; }

    public Guid MonitorEndpointId { get; set; }
    public MonitorEndpoint MonitorEndpoint { get; set; } = null!;
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;

    /// <summary>How the link was established: "probe" | "internal-probe" | "manual" | "deployment".</summary>
    public string Source { get; set; } = "probe";

    /// <summary>
    /// How sure RemoteSSL is that this endpoint really serves this certificate (§5.2):
    /// 100 for a direct observation, lower for inferred links. Kept as an integer percentage
    /// so the UI can rank ambiguous correlations.
    /// </summary>
    public int Confidence { get; set; } = 100;
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
}
