[CmdletBinding()]
param(
    [switch]$SkipBrowser
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ScriptsDir = $PSScriptRoot
$LogsDir = Join-Path $ProjectRoot 'logs'
$TokenFile = Join-Path $ScriptsDir '.proxy_token'
$ProxyLauncher = Join-Path $ScriptsDir 'Start-Ollama-Proxy.ps1'
$AppLauncher = Join-Path $ScriptsDir 'Start-VibeSec.ps1'
$TunnelRunner = Join-Path $ScriptsDir 'Run-VibeSec-Tunnel.ps1'
$ConnectionViewer = Join-Path $ScriptsDir 'Show-VibeSec-Connection.ps1'
$TunnelUrlFile = Join-Path $LogsDir 'cloudflare-url.txt'
$PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Write-Section([string]$Message) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Test-LocalOllama {
    try {
        $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3 -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Test-TcpPort([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne(800)
        if ($ok -and $client.Connected) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    } catch { return $false }
    finally { $client.Close() }
}

function Test-AuthenticatedProxy([string]$Token) {
    if (-not $Token) { return $false }
    try {
        $headers = @{ Authorization = "Bearer $Token" }
        $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/tags' -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Start-PowerShellWindow([string]$ScriptPath, [string]$ExtraArguments = '') {
    if (-not (Test-Path $ScriptPath)) { throw "Required script not found: $ScriptPath" }
    $arguments = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$ScriptPath`" $ExtraArguments"
    Start-Process -FilePath $PowerShellExe -ArgumentList $arguments -WorkingDirectory $ProjectRoot | Out-Null
}

function Find-Cloudflared {
    $cmd = Get-Command cloudflared.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'cloudflared\cloudflared.exe'),
        (Join-Path $env:ProgramFiles 'cloudflared\cloudflared.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\cloudflared.exe')
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    return $null
}

New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
Set-Location $ProjectRoot

Write-Section 'VibeSec One-Click Startup'
Write-Host "Project: $ProjectRoot" -ForegroundColor Gray
Write-Host 'This launcher reuses healthy services and avoids printing your full token.' -ForegroundColor Gray

# 1. Ollama
Write-Section '1/4  Ollama model service'
if (Test-LocalOllama) {
    Write-Host '[OK] Ollama is already running on 127.0.0.1:11434.' -ForegroundColor Green
} else {
    $ollama = Get-Command ollama.exe -ErrorAction SilentlyContinue
    if (-not $ollama) { $ollama = Get-Command ollama -ErrorAction SilentlyContinue }
    if (-not $ollama) {
        Write-Host '[ERROR] Ollama was not found. Install/start Ollama, then run this launcher again.' -ForegroundColor Red
        throw 'Ollama executable not found.'
    }
    Write-Host '[INFO] Ollama is offline. Opening a separate terminal for ollama serve...' -ForegroundColor Yellow
    Start-Process -FilePath $PowerShellExe -ArgumentList '-NoProfile -NoExit -Command "ollama serve"' -WorkingDirectory $ProjectRoot | Out-Null
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Seconds 1
        if (Test-LocalOllama) { $ready = $true; break }
    }
    if (-not $ready) { throw 'Ollama did not become ready within 40 seconds. Check its terminal.' }
    Write-Host '[OK] Ollama is ready.' -ForegroundColor Green
}

try {
    $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5
    $modelNames = @($tags.models | ForEach-Object { $_.name })
    if ($modelNames -contains 'qwen2.5-coder:7b') {
        Write-Host '[OK] qwen2.5-coder:7b is available.' -ForegroundColor Green
    } else {
        Write-Host "[WARN] qwen2.5-coder:7b not found. Available: $($modelNames -join ', ')" -ForegroundColor Yellow
        Write-Host 'Install it separately with: ollama pull qwen2.5-coder:7b' -ForegroundColor Yellow
    }
} catch { Write-Host '[WARN] Could not list Ollama models.' -ForegroundColor Yellow }

# 2. Authenticated proxy
Write-Section '2/4  Authenticated Ollama proxy'
if (-not (Test-Path $ProxyLauncher)) { throw "Missing existing proxy launcher: $ProxyLauncher" }
$token = $null
if (Test-Path $TokenFile) { $token = (Get-Content $TokenFile -Raw).Trim() }

if (Test-TcpPort 11435) {
    if (Test-AuthenticatedProxy $token) {
        Write-Host '[OK] Authenticated proxy is already running; reusing it.' -ForegroundColor Green
    } else {
        Write-Host '[ERROR] Port 11435 is occupied, but the saved token did not authenticate.' -ForegroundColor Red
        Write-Host 'Close the old proxy terminal, confirm scripts\.proxy_token exists, then run this launcher again.' -ForegroundColor Yellow
        throw 'Proxy port conflict or token mismatch.'
    }
} else {
    Write-Host '[INFO] Starting the existing Start-Ollama-Proxy.ps1 in a separate terminal...' -ForegroundColor Yellow
    Start-PowerShellWindow -ScriptPath $ProxyLauncher
    $proxyReady = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Seconds 1
        if ((Test-Path $TokenFile) -and (Test-TcpPort 11435)) {
            $token = (Get-Content $TokenFile -Raw).Trim()
            if (Test-AuthenticatedProxy $token) { $proxyReady = $true; break }
        }
    }
    if (-not $proxyReady) { throw 'Authenticated proxy did not become ready within 40 seconds. Check the proxy terminal.' }
    Write-Host '[OK] Authenticated proxy is ready. Token remains hidden.' -ForegroundColor Green
}

# 3. Cloudflare Quick Tunnel
Write-Section '3/4  Cloudflare Quick Tunnel'
$cloudflaredPath = Find-Cloudflared
if (-not $cloudflaredPath) {
    throw 'cloudflared.exe was not found. Install cloudflared or add it to PATH.'
}

$tunnelUrl = $null
$existingTunnel = @()
try {
    $existingTunnel = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '127\.0\.0\.1:11435' })
} catch { $existingTunnel = @() }

if ($existingTunnel.Count -gt 0) {
    if (Test-Path $TunnelUrlFile) { $tunnelUrl = (Get-Content $TunnelUrlFile -Raw).Trim() }
    if (-not $tunnelUrl -or -not (Test-AuthenticatedProxy $token)) {
        Write-Host '[ERROR] An older Cloudflare tunnel for port 11435 is already running.' -ForegroundColor Red
        Write-Host 'In its terminal press Ctrl+C, then run Start-VibeSec-Stack.bat again.' -ForegroundColor Yellow
        throw 'Existing tunnel detected; refusing to start a duplicate Quick Tunnel.'
    }
    Write-Host '[OK] Existing tunnel process detected; using its saved URL.' -ForegroundColor Green
} else {
    if (Test-Path $TunnelUrlFile) { Remove-Item $TunnelUrlFile -Force }
    Write-Host '[INFO] Opening Cloudflare tunnel in a separate terminal...' -ForegroundColor Yellow
    $extra = "-CloudflaredPath `"$cloudflaredPath`""
    Start-PowerShellWindow -ScriptPath $TunnelRunner -ExtraArguments $extra

    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 1
        if (Test-Path $TunnelUrlFile) {
            $candidate = (Get-Content $TunnelUrlFile -Raw).Trim()
            if ($candidate -match '^https://[a-zA-Z0-9-]+\.trycloudflare\.com$') {
                $tunnelUrl = $candidate
                break
            }
        }
    }
    if (-not $tunnelUrl) { throw 'Cloudflare URL was not detected after 60 seconds. Check the Cloudflare terminal.' }
    Write-Host '[OK] Cloudflare Quick Tunnel URL detected.' -ForegroundColor Green
}

# 4. Connection info terminal + local app
Write-Section '4/4  Connection details and VibeSec app'
$extra = "-TunnelUrl `"$tunnelUrl`""
Start-PowerShellWindow -ScriptPath $ConnectionViewer -ExtraArguments $extra
Write-Host '[OK] Opened a separate connection-details terminal.' -ForegroundColor Green
Write-Host 'In that window: U copies OLLAMA_URL; T copies the token; the full token is never printed.' -ForegroundColor Gray

if (-not (Test-Path $AppLauncher)) { throw "Missing existing VibeSec launcher: $AppLauncher" }
Write-Host '[INFO] Starting/reusing FastAPI and Express/Vite using the existing Start-VibeSec.ps1...' -ForegroundColor Yellow
& $AppLauncher -NoBrowser
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { Write-Host '[WARN] Start-VibeSec.ps1 returned a non-zero exit code.' -ForegroundColor Yellow }

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ' VibeSec startup sequence finished.' -ForegroundColor Green
Write-Host ' Local app:       http://localhost:3000' -ForegroundColor White
Write-Host ' Local FastAPI:   http://127.0.0.1:8000' -ForegroundColor White
Write-Host ' Public AI URL:   ' -NoNewline -ForegroundColor White
Write-Host $tunnelUrl -ForegroundColor Cyan
Write-Host ' Connection info: see the separate terminal (token is masked).' -ForegroundColor Gray
Write-Host ' To stop local VibeSec backend/gateway: .\scripts\Stop-VibeSec.ps1' -ForegroundColor Gray
Write-Host ' Stop proxy and Cloudflare by pressing Ctrl+C in their own terminals.' -ForegroundColor Gray
Write-Host '============================================================' -ForegroundColor Green

if (-not $SkipBrowser) {
    Start-Sleep -Seconds 2
    Start-Process 'http://localhost:3000' | Out-Null
}
