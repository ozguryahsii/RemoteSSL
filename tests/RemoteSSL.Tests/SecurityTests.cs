using RemoteSSL.Adapters.Ssh;
using RemoteSSL.Domain.Abstractions;

namespace RemoteSSL.Tests;

public class SecurityTests
{
    [Theory]
    [InlineData("/etc/nginx/ssl/a.crt", "'/etc/nginx/ssl/a.crt'")]
    [InlineData("a'; rm -rf / #", "'a'\\''; rm -rf / #'")]
    [InlineData("$(reboot)", "'$(reboot)'")]
    [InlineData("`id`", "'`id`'")]
    public void Shell_quote_neutralizes_injection(string input, string expected)
        => Assert.Equal(expected, Shell.Quote(input));

    [Fact]
    public void Job_signature_roundtrip_and_tamper_detection()
    {
        var jobId = Guid.NewGuid();
        var payload = """{"kind":"linux","certPath":"/etc/nginx/ssl/a.crt"}""";
        var token = JobSigner.Sign("secret", jobId, payload, DateTimeOffset.UtcNow.AddMinutes(10));

        Assert.True(JobSigner.Verify("secret", jobId, payload, token, DateTimeOffset.UtcNow));
        Assert.False(JobSigner.Verify("secret", jobId, payload.Replace("a.crt", "b.crt"), token, DateTimeOffset.UtcNow), "tampered payload");
        Assert.False(JobSigner.Verify("wrong", jobId, payload, token, DateTimeOffset.UtcNow), "wrong secret");
        Assert.False(JobSigner.Verify("secret", Guid.NewGuid(), payload, token, DateTimeOffset.UtcNow), "wrong job");
        Assert.False(JobSigner.Verify("secret", jobId, payload, token, DateTimeOffset.UtcNow.AddMinutes(11)), "expired");
    }
}
