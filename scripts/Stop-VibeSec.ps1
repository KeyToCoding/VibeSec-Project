# Stop-VibeSec.ps1
# Safely stops only VibeSec-managed processes without touching unrelated Node/Python instances
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogsDir = Join-Path $ProjectRoot "logs"
$PidFile = Join-Path $LogsDir "vibesec-pids.json"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "               Stopping VibeSec Suite               " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$StoppedCount = 0

function Verify-IsVibeSecProcess {
    param([int]$ProcessId)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if (-not $proc) { return $false }
        $cmd = [string]$proc.CommandLine
        $exe = [string]$proc.ExecutablePath

        # Check if the process command line or path contains VibeSec signatures
        if ($cmd -match "vibesec" -or
            $cmd -match "server\.ts" -or
            $cmd -match "uvicorn main:app" -or
            $exe -match "vibesec\\backend" -or
            $cmd -match "NIELIT Gorakhpur") {
            return $true
        }
    } catch {}
    return $false
}

function Safely-StopProcess {
    param([int]$ProcessId, [string]$ServiceName)

    if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
        Write-Host "[-] $ServiceName (PID: $ProcessId) is not currently running." -ForegroundColor Gray
        return $false
    }

    if (Verify-IsVibeSecProcess -ProcessId $ProcessId) {
        Write-Host "[*] Terminating $ServiceName (PID: $ProcessId)..." -ForegroundColor Yellow
        try {
            # Use taskkill /T /F to stop process and any spawned child worker processes
            cmd.exe /c "taskkill /PID $ProcessId /T /F" 2>&1 | Out-Null
            Write-Host "[OK] Stopped $ServiceName (PID: $ProcessId)." -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[!] Failed to cleanly stop PID $($ProcessId): $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] Refusing to terminate PID $($ProcessId): Does not match VibeSec signature. Unrelated process preserved." -ForegroundColor Magenta
    }
    return $false
}

# 1. Stop processes tracked in vibesec-pids.json
if (Test-Path $PidFile) {
    try {
        $RawContent = Get-Content -Path $PidFile -Raw -ErrorAction SilentlyContinue
        if ($RawContent) {
            $PidsData = $RawContent | ConvertFrom-Json
            if ($PidsData.backend -and $PidsData.backend.pid) {
                if (Safely-StopProcess -ProcessId ([int]$PidsData.backend.pid) -ServiceName "FastAPI Backend") {
                    $StoppedCount++
                }
            }
            if ($PidsData.frontend -and $PidsData.frontend.pid) {
                if (Safely-StopProcess -ProcessId ([int]$PidsData.frontend.pid) -ServiceName "Frontend Gateway") {
                    $StoppedCount++
                }
            }
        }
    } catch {
        Write-Host "[!] Error parsing $($PidFile): $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue
}

# 2. Check for any remaining VibeSec processes bound to port 8000 or 3000
function Check-And-Stop-PortListener {
    param([int]$Port, [string]$Name)
    try {
        $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        foreach ($c in $connections) {
            if ($c.OwningProcess -and $c.OwningProcess -gt 0) {
                $pidVal = [int]$c.OwningProcess
                if (Verify-IsVibeSecProcess -ProcessId $pidVal) {
                    Write-Host "[*] Detected residual $Name listener on port $Port (PID: $pidVal)." -ForegroundColor Yellow
                    if (Safely-StopProcess -ProcessId $pidVal -ServiceName "$Name (Port $Port)") {
                        $script:StoppedCount++
                    }
                }
            }
        }
    } catch {}
}

Check-And-Stop-PortListener -Port 8000 -Name "FastAPI Backend"
Check-And-Stop-PortListener -Port 3000 -Name "Frontend Gateway"

# 3. Final verification of ports
Start-Sleep -Milliseconds 500
$Port8000InUse = [bool](Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue)
$Port3000InUse = [bool](Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue)

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "                VibeSec Stop Summary                " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Processes stopped   : $StoppedCount" -ForegroundColor White
Write-Host "  Port 8000 (Backend) : $(if ($Port8000InUse) { 'STILL IN USE' } else { 'CLEARED / AVAILABLE' })" -ForegroundColor $(if ($Port8000InUse) { 'Red' } else { 'Green' })
Write-Host "  Port 3000 (Frontend): $(if ($Port3000InUse) { 'STILL IN USE' } else { 'CLEARED / AVAILABLE' })" -ForegroundColor $(if ($Port3000InUse) { 'Red' } else { 'Green' })
Write-Host "====================================================" -ForegroundColor Cyan
