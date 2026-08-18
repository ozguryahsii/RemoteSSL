# Installing RemoteSSL on a Windows server

This is the install for a Windows test or management server: one machine that runs the control
plane, the web UI and a runner, and reaches the estate from inside the network.

The runner belongs on Windows for a reason. WinRM / PowerShell Remoting is the primary management
channel for Windows targets (design doc §11.1), and it is executed natively from a Windows runner —
IIS bindings, the certificate store and non-exportable keys all go through it. Linux targets are
reached over SSH from the same runner, so one machine covers both.

## What ends up on the machine

| Part | What it is | Where |
| --- | --- | --- |
| `RemoteSSL API` service | Control plane **and** the web UI, on one port | `C:\RemoteSSL\api` |
| `RemoteSSL Runner` service | Probes endpoints, performs deployments | `C:\RemoteSSL\runner` |
| PostgreSQL | The only required external dependency | wherever you put it |

The UI is built into the API's `wwwroot`, so one address serves the screens and the API: no second
web server, no CORS list to maintain, nothing to keep in step when the hostname changes.

RabbitMQ and Redis are optional. They are notification transport and cache; leave them out of the
configuration and the health endpoint will not report them at all.

---

## 1. Prerequisites on the server

Install these first (all are ordinary MSI/EXE installers):

| Needed | Version | Why |
| --- | --- | --- |
| [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) | 8.0.x | builds and runs both services |
| [Node.js](https://nodejs.org/) | 20 LTS or newer | builds the UI |
| [Git](https://git-scm.com/download/win) | any | to pull the source |
| [PostgreSQL](https://www.postgresql.org/download/windows/) | 14 or newer | the database |

After installing, open a **new** PowerShell so `dotnet`, `npm` and `git` are on `PATH`:

```powershell
dotnet --version   # 8.x
node --version     # v20+ or newer
```

> If the server has no internet access, see [Installing without internet access](#installing-without-internet-access).

### Create the database

In pgAdmin, or with `psql` from an elevated PowerShell:

```powershell
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE USER remotessl WITH PASSWORD 'ChangeThisPassword';"
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE DATABASE remotessl OWNER remotessl;"
```

The tables are created by the API itself on first start — migrations run on startup, so there is
nothing else to apply.

---

## 2. Get the code

```powershell
cd C:\
git clone https://github.com/ozguryahsii/RemoteSSL.git src\RemoteSSL
cd C:\src\RemoteSSL
git checkout claude/tls-lifecycle-manager-qv7tc5
```

---

## 3. Install

From an **elevated** PowerShell (Run as Administrator):

```powershell
cd C:\src\RemoteSSL
.\deploy\windows\Install-RemoteSSL.ps1 `
    -DbConnection "Host=localhost;Port=5432;Database=remotessl;Username=remotessl;Password=ChangeThisPassword" `
    -AdminPassword "Str0ng!Pass" `
    -Port 5200
```

If PowerShell refuses to run the script, allow it for this session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The script builds the UI and both services, writes their configuration, registers
`RemoteSSL API` and `RemoteSSL Runner` as automatic-start Windows services, opens the port in the
firewall and starts everything. It prints the bootstrap token it generated — keep it if you plan to
add runners on other machines.

**Open** `http://<server-name>:5200` and sign in as `admin` with the password you passed.

Leaving `-AdminPassword` out turns authentication off entirely: anyone who can reach the port gets
full access. That is only reasonable on an isolated test network.

The admin account is created **once**, on the first start against an empty database. Passing a
different `-AdminPassword` later does not change it — from then on accounts and passwords are
managed in the UI under **Setup → Users**.

---

## 4. First checks

```powershell
Get-Service 'RemoteSSL*'
Invoke-WebRequest http://localhost:5200/health -UseBasicParsing | Select-Object -Expand Content
```

`Healthy` means the database is reachable. In the UI, **Setup → Runners** should list this machine
as Online within a few seconds — deployments and discovery only run while a runner is up.

---

## 5. Reaching your targets

### Windows targets (IIS, certificate store, CCS)

The runner talks to them over PowerShell Remoting. On each target, as an administrator:

```powershell
Enable-PSRemoting -Force
```

If the target is not in the same domain as the RemoteSSL server, tell the **RemoteSSL server** it
may connect to it:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "target1,target2" -Concatenate -Force
```

Then in the UI: **Setup → Credentials** → add the account (domain\user or .\user with its
password), **Servers → Add target** → adapter `IIS` or `Windows certificate store`, host and
credential. Port 5985 is plain WinRM, 5986 is over TLS.

### Linux targets (nginx, Apache, HAProxy, files)

SSH is spoken by the runner directly, so nothing needs installing on the server. Add the target
with adapter `nginx` (or whichever applies), host, port 22 and either a password or an SSH key
credential.

### Seeing what a machine actually serves

On a target row, **What's on it?** asks the machine which sites it is serving and with which
certificate — IIS bindings, nginx `server` blocks. Tick the sites and use **Replace certificate on
N site(s)** to install a new certificate exactly where the old one is in use.

---

## 6. Updating to a newer version

```powershell
cd C:\src\RemoteSSL
git pull origin claude/tls-lifecycle-manager-qv7tc5
.\deploy\windows\Install-RemoteSSL.ps1 -DbConnection "…" -AdminPassword "…"
```

Re-running is the update: services are stopped, republished and started again, and schema changes
are applied on startup. Take a database backup first if the data matters to you:

```powershell
& "C:\Program Files\PostgreSQL\16\bin\pg_dump.exe" -U remotessl remotessl > C:\backup\remotessl.sql
```

---

## Serving it over HTTPS

A tool that manages certificates should not be served over plain HTTP for long. Kestrel can use a
certificate from the machine's own store — add this to
`C:\RemoteSSL\api\appsettings.Production.json` and restart the service:

```json
{
  "Urls": "https://0.0.0.0:5200",
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "https://0.0.0.0:5200",
        "Certificate": { "Subject": "remotessl.your.domain", "Store": "My", "Location": "LocalMachine" }
      }
    }
  }
}
```

The UI calls whatever address served it, so nothing else changes.

---

## Installing without internet access

Build on a machine that has internet, copy the result over, and skip the build on the server:

```powershell
# On the build machine, from the repository root:
cd frontend; $env:VITE_API_BASE=''; npm ci; npm run build; cd ..
dotnet publish src\RemoteSSL.Api    -c Release -o out\api
dotnet publish src\RemoteSSL.Runner -c Release -o out\runner
Copy-Item frontend\dist out\api\wwwroot -Recurse
```

Copy `out\` to the server as `C:\RemoteSSL\`, then create the two `appsettings.Production.json`
files (the script's contents are the template — database connection, bootstrap token, admin
password) and register the services:

```powershell
New-Service -Name 'RemoteSSL API'    -BinaryPathName '"C:\RemoteSSL\api\RemoteSSL.Api.exe"'       -StartupType Automatic
New-Service -Name 'RemoteSSL Runner' -BinaryPathName '"C:\RemoteSSL\runner\RemoteSSL.Runner.exe"' -StartupType Automatic
Start-Service 'RemoteSSL API'; Start-Service 'RemoteSSL Runner'
```

Only the .NET 8 **runtime** (ASP.NET Core Hosting Bundle) is needed on the server in this case, not
the SDK.

---

## When something does not start

| Symptom | Where to look |
| --- | --- |
| A service stops right after starting | `Get-EventLog -LogName Application -Source 'RemoteSSL*' -Newest 20` — a bad connection string shows up here |
| `/health` says `Unhealthy` | PostgreSQL is down, the password is wrong, or the firewall on the database host blocks 5432 |
| UI loads but every screen is empty | The API is fine but the browser was served from a different address than it calls; re-run the installer so the UI is rebuilt with an empty `VITE_API_BASE` |
| Runner never appears under Setup → Runners | The bootstrap tokens in the two `appsettings.Production.json` files differ, or `ControlPlane:Url` points somewhere unreachable |
| Windows target: `Access is denied` | The credential is not an administrator on the target, or the target is not in `TrustedHosts` on the RemoteSSL server |
| Windows target: `Cannot connect` | `Enable-PSRemoting` was not run there, or 5985/5986 is closed |

To run a service in the foreground and watch it, stop the service and start the executable by hand:

```powershell
Stop-Service 'RemoteSSL API'
C:\RemoteSSL\api\RemoteSSL.Api.exe
```
