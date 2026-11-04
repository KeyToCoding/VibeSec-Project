<#
.SYNOPSIS
    Stops all running VibeSec services (FastAPI, Express Gateway, Proxy, and Cloudflare Tunnel).
#>
[CmdletBinding()]
param()

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                Stopping ALL VibeSec Services               " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Stop App Services (FastAPI + Express)
$stopApp = Join-Path $PSScriptRoot "Stop-VibeSec.ps1"
if (Test-Path $stopApp) {
    & $stopApp
}

# Stop Tunnel + Proxy
$stopTunnel = Join-Path $PSScriptRoot "Stop-VibeSec-Tunnel.ps1"
if (Test-Path $stopTunnel) {
    & $stopTunnel
}

Write-Host "`n[OK] All VibeSec services stopped." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

