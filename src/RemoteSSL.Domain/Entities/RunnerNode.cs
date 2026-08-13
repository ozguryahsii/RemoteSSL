namespace RemoteSSL.Domain.Entities;

/// <summary>
/// An execution node living inside a network segment. Connects outbound (mTLS) to the
/// control plane, publishes its capabilities via heartbeat and executes deployment
/// jobs against targets it can reach; the control plane never connects to targets
/// directly.
/// </summary>
public class RunnerNode
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Segment { get; set; }
    public RunnerStatus Status { get; set; }

    /// <summary>Capabilities advertised via heartbeat, e.g. ["ssh","winrm","openssl","keytool"].</summary>
    public string CapabilitiesJson { get; set; } = "[]";
    public string? Version { get; set; }

    /// <summary>SHA-256 thumbprint of the runner's client identity certificate.</summary>
    public string? IdentityCertThumbprint { get; set; }

    public DateTimeOffset? LastHeartbeatAt { get; set; }
    public DateTimeOffset RegisteredAt { get; set; }
}
