using System.Security.Cryptography;
using System.Text;

namespace RemoteSSL.Domain.Abstractions;

/// <summary>
/// Short-lived signed job context (design doc §8.2): the control plane signs
/// jobId + payload hash + expiry with a shared secret; the runner refuses jobs with
/// missing/expired/forged signatures. Complements transport security (mTLS is
/// terminated by infrastructure in production).
/// </summary>
public static class JobSigner
{
    public static string Sign(string secret, Guid jobId, string payloadJson, DateTimeOffset expiresAt)
    {
        var payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payloadJson)));
        var message = $"{jobId:N}|{payloadHash}|{expiresAt.ToUnixTimeSeconds()}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var sig = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(message)));
        return $"{expiresAt.ToUnixTimeSeconds()}.{sig}";
    }

    public static bool Verify(string secret, Guid jobId, string payloadJson, string token, DateTimeOffset now)
    {
        var parts = token.Split('.', 2);
        if (parts.Length != 2 || !long.TryParse(parts[0], out var exp)) return false;
        if (DateTimeOffset.FromUnixTimeSeconds(exp) < now) return false;
        var expected = Sign(secret, jobId, payloadJson, DateTimeOffset.FromUnixTimeSeconds(exp));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(token));
    }
}
