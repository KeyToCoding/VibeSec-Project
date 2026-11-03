$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$TokenFile = Join-Path $PSScriptRoot '.proxy_token'
$UrlFile = Join-Path $ProjectRoot 'logs\cloudflare-url.txt'
Set-Location $ProjectRoot

Write-Host '[START] VibeSec connection details terminal' -ForegroundColor Cyan
Write-Host '[WAIT] Waiting for the Cloudflare tunnel URL...' -ForegroundColor Yellow
for ($i = 0; $i -lt 150; $i++) {
    if ((Test-Path $UrlFile) -and (Test-Path $TokenFile)) { break }
    Start-Sleep -Seconds 1
}
if (-not (Test-Path $UrlFile)) { throw 'Cloudflare URL was not created. Check the Cloudflare Tunnel terminal.' }
if (-not (Test-Path $TokenFile)) { throw 'scripts/.proxy_token is missing. Start the authenticated proxy first.' }

$url = (Get-Content -LiteralPath $UrlFile -Raw).Trim()
$token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($url -notmatch '^https://[a-zA-Z0-9-]+\.trycloudflare\.com$') { throw 'The saved Cloudflare URL does not look valid.' }
if ($token.Length -lt 16) { throw 'The saved proxy token is empty or invalid.' }

Clear-Host
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '       VibeSec — Render FastAPI Connection Details' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Render > vibesec-fastapi > Environment' -ForegroundColor Gray
Write-Host ''
Write-Host 'OLLAMA_URL' -ForegroundColor Yellow
Write-Host $url -ForegroundColor White
Write-Host ''
Write-Host 'OLLAMA_PROXY_TOKEN' -ForegroundColor Yellow
Write-Host $token -ForegroundColor White
Write-Host ''
Write-Host 'IMPORTANT: This token is displayed only in this local terminal.' -ForegroundColor Red
Write-Host 'Do not take/share screenshots of this terminal or paste the token into chat, code, logs, or GitHub.' -ForegroundColor Red
Write-Host 'The token is read from scripts/.proxy_token and is NOT written to a new file.' -ForegroundColor Gray
Write-Host ''
Write-Host '[READY] Connection details are displayed above. This terminal will remain open.' -ForegroundColor Green
while ($true) { Start-Sleep -Seconds 60 }
