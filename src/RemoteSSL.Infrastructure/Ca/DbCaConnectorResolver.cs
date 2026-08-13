using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Requests;
using RemoteSSL.Application.Observability;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Infrastructure.Ca;

public class DbCaConnectorResolver(IRemoteSslDbContext db, CaConnectorFactory factory, MetricsRecorder metrics) : ICaConnectorResolver
{
    public async Task<ICertificateAuthorityConnector> ResolveAsync(Guid caConnectorId, CancellationToken ct)
    {
        var cfg = await db.CaConnectors.AsNoTracking().FirstOrDefaultAsync(c => c.Id == caConnectorId && c.Enabled, ct)
                  ?? throw new KeyNotFoundException($"CA connector {caConnectorId} not found or disabled");
        // Decorated so every CA call feeds ca_request_latency (§32.1).
        return new MeasuredCaConnector(factory.Create(cfg.ConnectorType, cfg.EncryptedConfigJson), metrics);
    }
}
