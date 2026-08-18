# RemoteSSL

Certificate Lifecycle Management (CLM) & Remote Deployment Platform: SSL monitoring, certificate
inventory, lifecycle automation and transactional remote deployment in one product.

See `docs/phases.md` for the development roadmap and `docs/ca-connector.md` for the CA-agnostic
connector design.

## Repository layout

```
src/RemoteSSL.Domain/          Entities, enums, adapter SDK + CA connector contracts
src/RemoteSSL.Application/     Application services (from F1)
src/RemoteSSL.Infrastructure/  EF Core (PostgreSQL), messaging, external services
src/RemoteSSL.Api/             ASP.NET Core Web API (Swagger, health checks)
src/RemoteSSL.Runner/          Execution node worker (job engine from F2)
tests/RemoteSSL.Tests/         Unit tests
frontend/                      React + TypeScript (Vite) admin UI
docker-compose.yml             PostgreSQL + RabbitMQ + Redis for local development
```

## Local development (macOS / Linux)

Prerequisites: .NET 8 SDK, Node.js 20+, Docker.

```bash
# 1. Infrastructure
docker compose up -d

# 2. API (applies DB migrations automatically on startup)  → http://localhost:5200 (Swagger at /swagger, health at /health)
dotnet run --project src/RemoteSSL.Api

# 3. Frontend → http://localhost:5173
cd frontend && npm install && npm run dev
```

Default local credentials (development only) live in `docker-compose.yml` and
`src/RemoteSSL.Api/appsettings.json`.

## Windows server install

For a real (test or management) server, `docs/WINDOWS-INSTALL.md` walks through it end to end:
PostgreSQL, one elevated PowerShell command, and RemoteSSL runs as two Windows services with the
UI served from the same port as the API.

```powershell
.\deploy\windows\Install-RemoteSSL.ps1 -DbConnection "Host=localhost;…" -AdminPassword "…"
```

The runner belongs on Windows: WinRM / PowerShell Remoting is the primary management channel for
Windows targets (§11.1), and Linux targets are reached over SSH from the same machine.

## Build & test

```bash
dotnet build
dotnet test
cd frontend && npm run build
```
