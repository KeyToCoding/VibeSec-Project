$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$AppLauncher = Join-Path $PSScriptRoot 'Start-VibeSec.ps1'
$LogsDir = Join-Path $ProjectRoot 'logs'
$BackendLog = Join-Path $LogsDir 'vibesec-backend.log'
$FrontendLog = Join-Path $LogsDir 'vibesec-frontend.log'
Set-Location $ProjectRoot

function Test-Url([string]$Url) {
    try { $null = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop; return $true }
    catch {
        # A protected health path can return a non-2xx result while the web service itself is still reachable.
        return ($_.Exception.Response -ne $null)
    }
}

Write-Host '[START] VibeSec application terminal' -ForegroundColor Cyan
if (-not (Test-Path $AppLauncher)) { throw "Existing app launcher not found: $AppLauncher" }
Write-Host '[INFO] Calling the existing Start-VibeSec.ps1 (FastAPI + Express gateway)...' -ForegroundColor Yellow
& $AppLauncher -NoBrowser
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Start-VibeSec.ps1 returned exit code $LASTEXITCODE" }

$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    if ((Test-Url 'http://127.0.0.1:8000/api/health') -and (Test-Url 'http://127.0.0.1:3000')) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw 'VibeSec services were started but the local health checks did not both respond. Inspect logs/vibesec-backend.log and logs/vibesec-frontend.log.' }

Write-Host '[READY] VibeSec app is available at http://localhost:3000' -ForegroundColor Green
Write-Host '[INFO] Opening the application in your browser...' -ForegroundColor Gray
Start-Process 'http://localhost:3000' | Out-Null
Write-Host '[INFO] Following FastAPI and Express logs below. Press Ctrl+C to close this log viewer; app services will remain managed by Start-VibeSec.ps1.' -ForegroundColor Yellow
New-Item -ItemType File -Path $BackendLog -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType File -Path $FrontendLog -Force -ErrorAction SilentlyContinue | Out-Null
Get-Content -LiteralPath @($BackendLog, $FrontendLog) -Tail 15 -Wait

