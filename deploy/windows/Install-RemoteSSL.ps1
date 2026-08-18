<#
.SYNOPSIS
    Installs RemoteSSL (control plane + UI + runner) on a Windows server.

.DESCRIPTION
    Builds the solution and the UI from this working copy, publishes both services under
    -InstallRoot, writes their configuration, and registers them as Windows services so they start
    with the machine.

    The UI is published into the API's wwwroot, so one service serves both the screens and the API
    on one port: no second web server, no CORS list, one address to open.

    The runner is installed on this machine on purpose - WinRM / PowerShell Remoting is the primary
    management channel for Windows targets (design doc section 11.1), and it is executed from a Windows
    runner.

.PARAMETER InstallRoot
    Where the services are installed. Default C:\RemoteSSL.

.PARAMETER Port
    The port the control plane listens on. Default 5200.

.PARAMETER DbConnection
    PostgreSQL connection string. The database is created by the API on first start (migrations run
    on startup), but the server, the login and an empty database must exist first.

.PARAMETER BootstrapToken
    Shared secret the runner registers with. A random one is generated when this is not given.

.PARAMETER AdminPassword
    Turns on authentication and sets the admin password. Without it the control plane is left open
    to anyone who can reach the port - acceptable only on an isolated test network.

    The account is seeded once, against an empty database; afterwards passwords are changed in the
    UI under Setup -> Users, and a different value here has no effect.

.EXAMPLE
    .\Install-RemoteSSL.ps1 -DbConnection "Host=localhost;Port=5432;Database=remotessl;Username=remotessl;Password=Secret1" -AdminPassword "Str0ng!Pass"

.NOTES
    Run from an elevated PowerShell. Re-running is safe: services are stopped, republished and
    started again.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\RemoteSSL',
    [int]$Port = 5200,
    [Parameter(Mandatory = $true)][string]$DbConnection,
    [string]$BootstrapToken,
    [string]$AdminPassword,
    [string]$RunnerName = "$env:COMPUTERNAME-runner",
    [string]$RunnerSegment = 'default',
    [switch]$SkipFirewallRule
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($message) { Write-Host "`n=== $message" -ForegroundColor Cyan }
# Windows PowerShell 5.1 runs on .NET Framework, where RandomNumberGenerator has no static
# GetBytes - the instance method is the one both frameworks have.
# npm, dotnet and sc.exe all write ordinary notices to stderr, and with ErrorActionPreference
# 'Stop' PowerShell turns any of that into a terminating error - an npm version notice was enough
# to abort an install. The exit code is the only thing that says whether a native command failed,
# so that is what is checked.
function Invoke-Native([scriptblock]$command, [string]$what) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $command 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" }
}

function New-RandomSecret($byteCount) {
    $bytes = New-Object byte[] $byteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}
function Need($command, $hint) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command not found. $hint"
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell - registering services requires it.'
}

$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Step "Installing from $repo"

Need dotnet 'Install the .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0'
Need npm    'Install Node.js 20 or newer: https://nodejs.org/'

if (-not $BootstrapToken) {
    $BootstrapToken = New-RandomSecret 32
    Write-Host "Generated a runner bootstrap token." -ForegroundColor Yellow
}

$apiDir    = Join-Path $InstallRoot 'api'
$runnerDir = Join-Path $InstallRoot 'runner'

# ---------------------------------------------------------------- stop what is already running
foreach ($name in 'RemoteSSL Runner', 'RemoteSSL API') {
    $existing = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -ne 'Stopped') {
        Step "Stopping $name"
        Stop-Service -Name $name -Force
        $existing.WaitForStatus('Stopped', '00:00:30')
    }
}

# ---------------------------------------------------------------- build
Step 'Building the UI'
Push-Location (Join-Path $repo 'frontend')
try {
    if (Test-Path 'package-lock.json') { Invoke-Native { npm ci } 'npm ci' }
    else { Invoke-Native { npm install } 'npm install' }
    # Empty base URL: the UI calls the API it was served from, whatever address that is.
    $env:VITE_API_BASE = ''
    Invoke-Native { npm run build } 'npm run build'
}
finally { Pop-Location }

Step "Publishing the control plane to $apiDir"
Invoke-Native { dotnet publish (Join-Path $repo 'src\RemoteSSL.Api') -c Release -o $apiDir } 'dotnet publish (API)'

Step "Publishing the runner to $runnerDir"
Invoke-Native { dotnet publish (Join-Path $repo 'src\RemoteSSL.Runner') -c Release -o $runnerDir } 'dotnet publish (runner)'

Step 'Placing the UI inside the control plane'
$wwwroot = Join-Path $apiDir 'wwwroot'
if (Test-Path $wwwroot) { Remove-Item $wwwroot -Recurse -Force }
Copy-Item (Join-Path $repo 'frontend\dist') $wwwroot -Recurse

# ---------------------------------------------------------------- configuration
Step 'Writing configuration'

# Windows PowerShell 5.1 cannot assign from an `if`, so the value is settled first.
$authEnabled = [bool]$AdminPassword
$adminPasswordValue = ''
if ($AdminPassword) { $adminPasswordValue = $AdminPassword }

$apiSettings = [ordered]@{
    Urls              = "http://0.0.0.0:$Port"
    ConnectionStrings = [ordered]@{ Database = $DbConnection }
    Database          = [ordered]@{ MigrateOnStartup = $true }
    Runner            = [ordered]@{ BootstrapToken = $BootstrapToken }
    Auth              = [ordered]@{
        Enabled       = $authEnabled
        JwtSecret     = New-RandomSecret 48
        AdminUsername = 'admin'
        AdminPassword = $adminPasswordValue
    }
}
# The queue and the cache are optional; leaving them out of the connection strings means the
# health endpoint does not report them, rather than reporting them down.
# Written without a byte-order mark: Windows PowerShell's UTF8 adds one, and configuration files
# are read by more than one tool here.
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $apiDir 'appsettings.Production.json'),
    ($apiSettings | ConvertTo-Json -Depth 6), $utf8)

$runnerSettings = [ordered]@{
    ControlPlane = [ordered]@{ Url = "http://localhost:$Port" }
    Runner       = [ordered]@{
        BootstrapToken = $BootstrapToken
        Name           = $RunnerName
        Segment        = $RunnerSegment
        PollSeconds    = 3
    }
}
[IO.File]::WriteAllText((Join-Path $runnerDir 'appsettings.Production.json'),
    ($runnerSettings | ConvertTo-Json -Depth 6), $utf8)

# Both files carry secrets (database password, bootstrap token, admin password), so they are
# readable by administrators and the service account only (section 22.3).
foreach ($file in (Join-Path $apiDir 'appsettings.Production.json'),
                  (Join-Path $runnerDir 'appsettings.Production.json')) {
    $acl = Get-Acl $file
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'Allow')))
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')))
    Set-Acl $file $acl
}

# ---------------------------------------------------------------- services
function Install-RemoteSslService($name, $exe, $description) {
    $existing = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($existing) {
        Step "Updating service $name"
        Invoke-Native { sc.exe config "$name" binPath= "`"$exe`"" start= auto } "sc config $name" | Out-Null
    }
    else {
        Step "Registering service $name"
        New-Service -Name $name -BinaryPathName "`"$exe`"" -DisplayName $name `
            -Description $description -StartupType Automatic | Out-Null
    }
    # Restart on failure rather than leaving the estate unmanaged after one bad night.
    Invoke-Native { sc.exe failure "$name" reset= 86400 actions= restart/30000/restart/60000/restart/120000 } `
        "sc failure $name" | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" `
        -Name Environment -Type MultiString `
        -Value @('DOTNET_ENVIRONMENT=Production', 'ASPNETCORE_ENVIRONMENT=Production')
}

Install-RemoteSslService 'RemoteSSL API' (Join-Path $apiDir 'RemoteSSL.Api.exe') `
    'RemoteSSL control plane: inventory, monitoring, deployment orchestration and the web UI.'
Install-RemoteSslService 'RemoteSSL Runner' (Join-Path $runnerDir 'RemoteSSL.Runner.exe') `
    'RemoteSSL execution node: probes endpoints and performs deployments on targets.'

if (-not $SkipFirewallRule) {
    Step "Opening TCP $Port"
    if (-not (Get-NetFirewallRule -DisplayName 'RemoteSSL' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'RemoteSSL' -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $Port | Out-Null
    }
}

Step 'Starting services'
Start-Service 'RemoteSSL API'
# The runner registers with the control plane, so it follows it.
Start-Sleep -Seconds 5
Start-Service 'RemoteSSL Runner'

Step 'Checking health'
# The first start applies migrations and seeds, and reports 503 until that finishes, so this waits
# rather than judging the install on a single early answer.
# Asked without a proxy: a machine configured to send everything through one answers 503 for
# localhost, which looks exactly like a broken install and is not one.
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.UseProxy = $false
$client = New-Object System.Net.Http.HttpClient($handler)
$client.Timeout = [TimeSpan]::FromSeconds(10)

$health = 'no answer'
$deadline = (Get-Date).AddMinutes(2)
while ((Get-Date) -lt $deadline) {
    try {
        $health = $client.GetStringAsync("http://localhost:$Port/health").GetAwaiter().GetResult()
        if ($health -eq 'Healthy') { break }
    }
    catch { $health = "not ready yet: $($_.Exception.InnerException.Message)" }
    Start-Sleep -Seconds 3
}
$client.Dispose()

Write-Host ""
Write-Host "RemoteSSL is installed." -ForegroundColor Green
Write-Host "  UI + API      http://$($env:COMPUTERNAME):$Port"
Write-Host "  Health        $health"
if ($health -ne 'Healthy') {
    Write-Host "  The control plane did not report healthy. Run it in the foreground to see why:" -ForegroundColor Yellow
    Write-Host "    Stop-Service 'RemoteSSL API'; $apiDir\RemoteSSL.Api.exe" -ForegroundColor Yellow
}
Write-Host "  Runner        $RunnerName (segment $RunnerSegment)"
if ($AdminPassword) {
    Write-Host "  Sign in       admin / the password you passed"
    Write-Host "                (seeded on an empty database only - change it under Setup -> Users)"
}
else { Write-Host "  Authentication is OFF - anyone who can reach the port has full access." -ForegroundColor Yellow }
Write-Host "  Bootstrap token: $BootstrapToken"
Write-Host ""
Write-Host "Logs: Get-EventLog -LogName Application -Source 'RemoteSSL*' -Newest 20"
