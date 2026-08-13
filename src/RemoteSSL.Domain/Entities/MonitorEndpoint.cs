namespace RemoteSSL.Domain.Entities;

/// <summary>
/// A credential-less TLS probe target: host/IP + port + optional SNI. Monitoring an
/// endpoint never requires credentials; adding credentials to the underlying system
/// happens on a separate <see cref="Target"/> entity, not here.
/// </summary>
public class MonitorEndpoint
{
    public Guid Id { get; set; }
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 443;
    public string? Sni { get; set; }
    public bool Enabled { get; set; } = true;

    /// <summary>Probe interval in minutes; policy default applies when null.</summary>
    public int? ProbeIntervalMinutes { get; set; }

    public ProbeStatus LastProbeStatus { get; set; }
    public string? LastProbeError { get; set; }
    public DateTimeOffset? LastProbeAt { get; set; }
    public Guid? LastObservedVersionId { get; set; }
    public CertificateVersion? LastObservedVersion { get; set; }

    public bool? LastHostnameValid { get; set; }
    public bool? LastChainValid { get; set; }
    public string? LastChainError { get; set; }
    public string? LastTlsProtocol { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<MonitorCertificateLink> CertificateLinks { get; set; } = new List<MonitorCertificateLink>();
}

/// <summary>
/// Many-to-many correlation between monitors and logical certificates. The same
/// certificate observed on several endpoints yields one Certificate and N links.
/// </summary>
public class MonitorCertificateLink
{
    public Guid MonitorEndpointId { get; set; }
    public MonitorEndpoint MonitorEndpoint { get; set; } = null!;
    public Guid CertificateId { get; set; }
    public Certificate Certificate { get; set; } = null!;

    /// <summary>How the link was established (e.g. "probe", "manual").</summary>
    public string Source { get; set; } = "probe";
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
}
