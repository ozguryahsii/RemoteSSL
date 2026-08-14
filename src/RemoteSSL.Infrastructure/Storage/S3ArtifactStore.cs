using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using RemoteSSL.Application.Artifacts;

namespace RemoteSSL.Infrastructure.Storage;

/// <summary>
/// S3-compatible artifact storage (design doc §4.3, §31.1). Content is already
/// envelope-encrypted before it reaches this class, so a bucket read yields ciphertext only;
/// server-side encryption and object-lock/versioning on the bucket are additional layers the
/// operator configures. Enabled by setting Storage:S3:BucketName — otherwise artifacts stay
/// in the database and this store is never selected.
/// </summary>
public class S3ArtifactStore : IArtifactObjectStore, IDisposable
{
    private readonly IAmazonS3? _client;
    private readonly string? _bucket;
    private readonly int _objectLockDays;
    private readonly ILogger<S3ArtifactStore> _logger;

    public string Provider => "s3";

    /// <summary>True when a bucket is configured; the service registration hides it otherwise.</summary>
    public bool Enabled => _client is not null && !string.IsNullOrWhiteSpace(_bucket);

    public S3ArtifactStore(IConfiguration configuration, ILogger<S3ArtifactStore> logger)
    {
        _logger = logger;
        _bucket = configuration["Storage:S3:BucketName"];
        // WORM (§25.3): with object lock configured, every object is written with a compliance
        // retain-until date, so nobody — including this application — can overwrite or delete it
        // before that date. The bucket itself must have object lock enabled.
        _objectLockDays = configuration.GetValue("Storage:S3:ObjectLockDays", 0);
        if (string.IsNullOrWhiteSpace(_bucket)) return;

        var config = new AmazonS3Config
        {
            // A service URL covers MinIO/Ceph and any other S3-compatible endpoint.
            ForcePathStyle = configuration.GetValue("Storage:S3:ForcePathStyle", true)
        };
        var serviceUrl = configuration["Storage:S3:ServiceUrl"];
        if (!string.IsNullOrWhiteSpace(serviceUrl)) config.ServiceURL = serviceUrl;
        else if (!string.IsNullOrWhiteSpace(configuration["Storage:S3:Region"]))
            config.RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(configuration["Storage:S3:Region"]);

        var accessKey = configuration["Storage:S3:AccessKey"];
        var secretKey = configuration["Storage:S3:SecretKey"];
        _client = string.IsNullOrWhiteSpace(accessKey)
            ? new AmazonS3Client(config)                       // instance/role credentials
            : new AmazonS3Client(accessKey, secretKey, config);

        _logger.LogInformation("S3 artifact storage enabled (bucket {Bucket})", _bucket);
    }

    public async Task PutAsync(string key, byte[] ciphertext, CancellationToken ct)
    {
        Require();
        using var stream = new MemoryStream(ciphertext);
        var request = new PutObjectRequest
        {
            BucketName = _bucket,
            Key = key,
            InputStream = stream,
            ContentType = "application/octet-stream",
            ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256
        };
        if (_objectLockDays > 0)
        {
            request.ObjectLockMode = ObjectLockMode.Compliance;
            request.ObjectLockRetainUntilDate = DateTime.UtcNow.AddDays(_objectLockDays);
        }
        await _client!.PutObjectAsync(request, ct);
    }

    public async Task<byte[]> GetAsync(string key, CancellationToken ct)
    {
        Require();
        using var response = await _client!.GetObjectAsync(_bucket, key, ct);
        using var buffer = new MemoryStream();
        await response.ResponseStream.CopyToAsync(buffer, ct);
        return buffer.ToArray();
    }

    public async Task DeleteAsync(string key, CancellationToken ct)
    {
        Require();
        await _client!.DeleteObjectAsync(_bucket, key, ct);
    }

    private void Require()
    {
        if (!Enabled) throw new InvalidOperationException(
            "S3 artifact storage is not configured (Storage:S3:BucketName is empty).");
    }

    public void Dispose() => _client?.Dispose();
}
