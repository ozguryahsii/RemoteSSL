using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using RemoteSSL.Runner;

var builder = Host.CreateApplicationBuilder(args);
// A runner belongs on the machine that manages Windows targets (§11.1), where it is expected to
// start with the server and keep running with nobody logged in. Ignored everywhere else, so the
// same build still runs from a console on Linux.
builder.Services.AddWindowsService(o => o.ServiceName = "RemoteSSL Runner");
builder.Services.AddHttpClient();
builder.Services.AddSingleton<RunnerSecretResolver>();
builder.Services.AddHostedService<Worker>();

// §32.2: the runner is the last leg of the request → CA → job → runner → target chain.
// Exported over OTLP only when a collector endpoint is configured.
var otlpEndpoint = builder.Configuration["Observability:OtlpEndpoint"];
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("remotessl-runner"))
    .WithTracing(t =>
    {
        t.AddSource(Worker.ActivitySourceName).AddHttpClientInstrumentation();
        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
            t.AddOtlpExporter(o => o.Endpoint = new Uri(otlpEndpoint));
    });

var host = builder.Build();
host.Run();
