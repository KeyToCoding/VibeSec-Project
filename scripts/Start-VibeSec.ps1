# Start-VibeSec.ps1
# Starts VibeSec services (FastAPI Backend + Node/Vite Gateway)
[CmdletBinding()]
param(
    [switch]$NoBrowser = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $ProjectRoot "vibesec\backend"
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
$LogsDir = Join-Path $ProjectRoot "logs"
$PidFile = Join-Path $LogsDir "vibesec-pids.json"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "               Starting VibeSec Suite               " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Ensure logs directory exists
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

# Load existing PID tracking if present
$ManagedProcesses = @{}
if (Test-Path $PidFile) {
    try {
        $RawContent = Get-Content -Path $PidFile -Raw -ErrorAction SilentlyContinue
        if ($RawContent) {
            $ManagedProcesses = $RawContent | ConvertFrom-Json -AsHashtable
        }
    } catch {
        $ManagedProcesses = @{}
    }
}

# 2. Check Ollama Status
Write-Host "`n[*] Checking Ollama Service (http://127.0.0.1:11434)..." -ForegroundColor Yellow
$OllamaOnline = $false
try {
    $OllamaResp = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -Method Get -TimeoutSec 2 -ErrorAction Stop
    $OllamaOnline = $true
    Write-Host "[OK] Ollama is online." -ForegroundColor Green
} catch {
    Write-Host "[!] Ollama is NOT responding at http://127.0.0.1:11434." -ForegroundColor DarkYellow
    Write-Host "    Note: AI Remediation & Chat require Ollama. Start Ollama ('ollama serve') when needed." -ForegroundColor Gray
}

# Helper: Test HTTP endpoint
function Test-HttpEndpoint {
    param([string]$Url, [int]$TimeoutSec = 2)
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        return ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 400)
    } catch {
        return $false
    }
}

# Helper: Get process listening on a port
function Get-PortListenerProcess {
    param([int]$Port)
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($conn -and $conn.OwningProcess) {
            return Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        }
    } catch {}
    return $null
}

# Helper: Start background daemon with direct file handle logging (prevents broken pipe when console exits)
function Start-VibeSecDaemon {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$LogFile
    )
    $escapedExe = $Executable.Replace('\', '\\')
    $escapedWd = $WorkingDirectory.Replace('\', '\\')
    $escapedLog = $LogFile.Replace('\', '\\')
    $argListPy = ($Arguments | ForEach-Object { "'" + $_.Replace('\', '\\').Replace("'", "\'") + "'" }) -join ", "

    $launcherPy = @"
import subprocess, sys
args = [$argListPy]
log = open(r'$escapedLog', 'a', encoding='utf-8', buffering=1)
p = subprocess.Popen([r'$escapedExe'] + args, cwd=r'$escapedWd', stdout=log, stderr=subprocess.STDOUT, creationflags=0x00000008)
print(p.pid)
"@
    $pidStr = & "$VenvPython" -c $launcherPy
    return [int]($pidStr.Trim())
}

# 3. Backend (FastAPI on Port 8000)
Write-Host "`n[*] Checking FastAPI Backend (Port 8000)..." -ForegroundColor Yellow
$BackendHealthy = Test-HttpEndpoint -Url "http://127.0.0.1:8000/api/health"

if ($BackendHealthy) {
    $ExistingProc = Get-PortListenerProcess -Port 8000
    $ExistingPid = if ($ExistingProc) { $ExistingProc.Id } else { "Unknown" }
    Write-Host "[OK] Backend is already running and healthy (PID: $ExistingPid). Reusing." -ForegroundColor Green
    if (-not $ManagedProcesses["backend"] -and $ExistingProc) {
        $ManagedProcesses["backend"] = @{
            pid = $ExistingProc.Id
            startedAt = (Get-Date).ToString("o")
            command = "reused-existing"
        }
    }
} else {
    if (-not (Test-Path $VenvPython)) {
        Write-Error "Backend virtual environment python not found at $VenvPython. Run .\scripts\Repair-VibeSec.ps1 first."
        exit 1
    }

    $PortConflict = Get-PortListenerProcess -Port 8000
    if ($PortConflict) {
        Write-Host "[!] Port 8000 is occupied by process $($PortConflict.ProcessName) (PID: $($PortConflict.Id)), but /api/health did not respond." -ForegroundColor Yellow
        Write-Host "    Attempting to proceed or wait..." -ForegroundColor Gray
    }

    Write-Host "[*] Launching FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Cyan
    $BackendLog = Join-Path $LogsDir "vibesec-backend.log"

    $BackendPid = Start-VibeSecDaemon `
        -Executable $VenvPython `
        -Arguments @("-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000") `
        -WorkingDirectory $BackendDir `
        -LogFile $BackendLog

    $ManagedProcesses["backend"] = @{
        pid = $BackendPid
        startedAt = (Get-Date).ToString("o")
        command = "$VenvPython -m uvicorn main:app --host 127.0.0.1 --port 8000"
    }

    Write-Host "[*] Backend process started (PID: $BackendPid). Waiting for health check..." -ForegroundColor Gray

    # Poll /api/health
    $BackendReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-HttpEndpoint -Url "http://127.0.0.1:8000/api/health") {
            $BackendReady = $true
            break
        }
        $procCheck = Get-Process -Id $BackendPid -ErrorAction SilentlyContinue
        if (-not $procCheck) {
            Write-Error "Backend process exited prematurely. Check $BackendLog."
            exit 1
        }
    }

    if ($BackendReady) {
        Write-Host "[OK] Backend is healthy on http://127.0.0.1:8000/api/health" -ForegroundColor Green
    } else {
        Write-Host "[!] Backend started but did not respond to health check in 15s. Check $BackendLog" -ForegroundColor Yellow
    }
}

# 4. Frontend (Express / Vite Gateway on Port 3000)
Write-Host "`n[*] Checking Frontend / Gateway (Port 3000)..." -ForegroundColor Yellow
$FrontendHealthy = Test-HttpEndpoint -Url "http://127.0.0.1:3000/api/health" -or (Test-HttpEndpoint -Url "http://127.0.0.1:3000")

if ($FrontendHealthy) {
    $ExistingProc = Get-PortListenerProcess -Port 3000
    $ExistingPid = if ($ExistingProc) { $ExistingProc.Id } else { "Unknown" }
    Write-Host "[OK] Frontend is already running and healthy (PID: $ExistingPid). Reusing." -ForegroundColor Green
    if (-not $ManagedProcesses["frontend"] -and $ExistingProc) {
        $ManagedProcesses["frontend"] = @{
            pid = $ExistingProc.Id
            startedAt = (Get-Date).ToString("o")
            command = "reused-existing"
        }
    }
} else {
    $NodeCli = Join-Path $ProjectRoot "node_modules\tsx\dist\cli.mjs"
    $ServerTs = Join-Path $ProjectRoot "server.ts"

    if (-not (Test-Path $NodeCli)) {
        Write-Error "tsx not found at $NodeCli. Run .\scripts\Repair-VibeSec.ps1 first."
        exit 1
    }

    Write-Host "[*] Launching Frontend Gateway on http://localhost:3000..." -ForegroundColor Cyan
    $FrontendLog = Join-Path $LogsDir "vibesec-frontend.log"

    $FrontendPid = Start-VibeSecDaemon `
        -Executable "node.exe" `
        -Arguments @($NodeCli, $ServerTs) `
        -WorkingDirectory $ProjectRoot `
        -LogFile $FrontendLog

    $ManagedProcesses["frontend"] = @{
        pid = $FrontendPid
        startedAt = (Get-Date).ToString("o")
        command = "node tsx server.ts"
    }

    Write-Host "[*] Frontend process started (PID: $FrontendPid). Waiting for health check..." -ForegroundColor Gray

    # Poll port 3000
    $FrontendReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-HttpEndpoint -Url "http://127.0.0.1:3000") {
            $FrontendReady = $true
            break
        }
        $procCheck = Get-Process -Id $FrontendPid -ErrorAction SilentlyContinue
        if (-not $procCheck) {
            Write-Error "Frontend process exited prematurely. Check $FrontendLog."
            exit 1
        }
    }

    if ($FrontendReady) {
        Write-Host "[OK] Frontend is healthy on http://localhost:3000" -ForegroundColor Green
    } else {
        Write-Host "[!] Frontend started but did not respond in 15s. Check $FrontendErrLog" -ForegroundColor Yellow
    }
}

# 5. Save Managed Process PIDs
$ManagedProcesses | ConvertTo-Json -Depth 4 | Set-Content -Path $PidFile -Encoding utf8
Write-Host "`n[OK] Process tracking saved to: $PidFile" -ForegroundColor Green

# 6. Summary Dashboard
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "              VibeSec Services Ready                " -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Frontend Application : http://localhost:3000" -ForegroundColor White
Write-Host "  FastAPI Backend API  : http://127.0.0.1:8000" -ForegroundColor White
Write-Host "  Backend Swagger Docs : http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "  Backend Health       : http://127.0.0.1:8000/api/health" -ForegroundColor White
Write-Host "  Ollama Local Model   : $(if ($OllamaOnline) { 'Online (http://127.0.0.1:11434)' } else { 'Offline / Not reachable' })" -ForegroundColor $(if ($OllamaOnline) { "Green" } else { "Yellow" })
Write-Host "  Backend Logs         : $LogsDir\vibesec-backend.log" -ForegroundColor Gray
Write-Host "  Frontend Logs        : $LogsDir\vibesec-frontend.log" -ForegroundColor Gray
Write-Host "----------------------------------------------------" -ForegroundColor Cyan
Write-Host "To gracefully stop only VibeSec services, run:" -ForegroundColor Gray
Write-Host "  .\scripts\Stop-VibeSec.ps1" -ForegroundColor Yellow
Write-Host "====================================================" -ForegroundColor Cyan

if (-not $NoBrowser) {
    Write-Host "`n[*] Opening http://localhost:3000 in your browser..." -ForegroundColor Cyan
    Start-Process "http://localhost:3000" | Out-Null
}
