using RemoteSSL.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddRemoteSslInfrastructure(builder.Configuration);

builder.Services.AddHealthChecks()
    .AddNpgSql(builder.Configuration.GetConnectionString("Database")!, name: "postgres")
    .AddRabbitMQ(rabbitConnectionString: builder.Configuration.GetConnectionString("RabbitMq")!, name: "rabbitmq")
    .AddRedis(builder.Configuration.GetConnectionString("Redis")!, name: "redis");

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? ["http://localhost:5173"])
    .AllowAnyHeader()
    .AllowAnyMethod()));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
