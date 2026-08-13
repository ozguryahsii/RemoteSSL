namespace RemoteSSL.Runner;

/// <summary>
/// Runner main loop skeleton. From F2 on this becomes: register with the control
/// plane via bootstrap token, obtain a client identity certificate, connect outbound
/// (mTLS), publish heartbeat + capabilities, and pull deployment jobs scoped to this
/// runner's segment.
/// </summary>
public class Worker(ILogger<Worker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("RemoteSSL Runner started (skeleton — job engine arrives in F2)");
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }
}
