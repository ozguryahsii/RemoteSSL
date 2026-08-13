using Microsoft.AspNetCore.DataProtection;
using RemoteSSL.Application.Abstractions;

namespace RemoteSSL.Infrastructure.Security;

public class DataProtectionSecretProtector(IDataProtectionProvider provider) : ISecretProtector
{
    private readonly IDataProtector _protector = provider.CreateProtector("RemoteSSL.Secrets.v1");

    public string Protect(string plaintext) => _protector.Protect(plaintext);
    public string Unprotect(string ciphertext) => _protector.Unprotect(ciphertext);
}
