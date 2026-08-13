using Microsoft.EntityFrameworkCore;
using RemoteSSL.Application.Abstractions;
using RemoteSSL.Application.Requests;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Infrastructure.Ca;

public class DbCaConnectorResolver(IRemoteSslDbContext db, CaConnectorFactory factory) : ICaConnectorResolver
{
    public async Task<ICertificateAuthorityConnector> ResolveAsync(Guid caConnectorId, CancellationToken ct)
    {
        var cfg = await db.CaConnectors.AsNoTracking().FirstOrDefaultAsync(c => c.Id == caConnectorId && c.Enabled, ct)
                  ?? throw new KeyNotFoundException($"CA connector {caConnectorId} not found or disabled");
        return factory.Create(cfg.ConnectorType, cfg.EncryptedConfigJson);
    }
}
