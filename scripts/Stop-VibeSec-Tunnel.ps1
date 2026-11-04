<#
.SYNOPSIS
    Stops the VibeSec Cloudflare Tunnel and Authenticated Ollama Proxy.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         Stopping VibeSec Remote AI Tunnel & Proxy          " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Stop cloudflared processes
$tunnels = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '11435' })
foreach ($t in $tunnels) {
    Write-Host "[*] Terminating cloudflared tunnel process (PID: $($t.ProcessId))..." -ForegroundColor Yellow
    Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue
}

# 2. Stop proxy listening on 11435
$conn = Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($conn -and $conn.OwningProcess) {
    Write-Host "[*] Terminating Authenticated Proxy process (PID: $($conn.OwningProcess))..." -ForegroundColor Yellow
    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
}

Write-Host "[OK] Remote AI Tunnel and Proxy stopped successfully." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

