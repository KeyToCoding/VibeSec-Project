[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CloudflaredPath
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$LogsDir = Join-Path $ProjectRoot 'logs'
$UrlFile = Join-Path $LogsDir 'cloudflare-url.txt'
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
if (-not (Test-Path $CloudflaredPath)) { throw "cloudflared executable not found: $CloudflaredPath" }
if (Test-Path $UrlFile) { Remove-Item $UrlFile -Force }

Write-Host 'VibeSec Cloudflare Quick Tunnel' -ForegroundColor Cyan
Write-Host 'Forwarding public traffic to authenticated local proxy 127.0.0.1:11435.' -ForegroundColor Gray
Write-Host 'Keep this window open while using hosted AI.' -ForegroundColor Yellow

& $CloudflaredPath tunnel --url 'http://127.0.0.1:11435' 2>&1 | ForEach-Object {
    $line = $_.ToString()
    Write-Host $line
    if ($line -match 'https://[a-zA-Z0-9-]+\.trycloudflare\.com') {
        $url = $Matches[0]
        Set-Content -Path $UrlFile -Value $url -Encoding ASCII -NoNewline
        Write-Host "`n[OK] Tunnel URL saved locally for the launcher: $UrlFile" -ForegroundColor Green
    }
}
