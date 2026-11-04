$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$TokenFile = Join-Path $PSScriptRoot '.proxy_token'
$UrlFile = Join-Path $ProjectRoot 'logs\cloudflare-url.txt'
Set-Location $ProjectRoot

Write-Host '[START] VibeSec connection details terminal' -ForegroundColor Cyan
Write-Host '[WAIT] Waiting for the Cloudflare tunnel URL...' -ForegroundColor Yellow
$scriptsUrl = Join-Path $PSScriptRoot '.tunnel_url'
for ($i = 0; $i -lt 150; $i++) {
    if (((Test-Path $UrlFile) -or (Test-Path $scriptsUrl)) -and (Test-Path $TokenFile)) { break }
    # If tunnel terminal indicated skipped, don't wait 150 seconds
    $tunnelOut = Join-Path $ProjectRoot 'logs\cloudflared-antigravity.stdout.log'
    $tunnelErr = Join-Path $ProjectRoot 'logs\cloudflared-antigravity.stderr.log'
    Start-Sleep -Seconds 1
}

$hasTunnel = $false
$url = ""
if (Test-Path $UrlFile) {
    $url = (Get-Content -LiteralPath $UrlFile -Raw).Trim()
    $hasTunnel = ($url -match '^https://[a-zA-Z0-9-]+\.trycloudflare\.com$')
} elseif (Test-Path $scriptsUrl) {
    $url = (Get-Content -LiteralPath $scriptsUrl -Raw).Trim()
    $hasTunnel = ($url -match '^https://[a-zA-Z0-9-]+\.trycloudflare\.com$')
}

$token = ""
if (Test-Path $TokenFile) {
    $token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
}

$maskedToken = if ($token.Length -ge 8) { "$($token.Substring(0, 4))...$($token.Substring($token.Length - 4))" } else { "****" }

$clipboardCopied = $false
if ($token) {
    try {
        Set-Clipboard -Value $token
        $clipboardCopied = $true
    } catch {}
}

Clear-Host
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '       VibeSec — AI Connection & Operating Details          ' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Local Operating Mode (Default):' -ForegroundColor Yellow
Write-Host '  Web Interface    : http://localhost:3000' -ForegroundColor White
Write-Host '  FastAPI Backend  : http://127.0.0.1:8000' -ForegroundColor White
Write-Host '  Local Ollama     : http://127.0.0.1:11434' -ForegroundColor White
Write-Host '  Status           : Fully functional locally without cloud dependencies' -ForegroundColor Green
Write-Host ''

if ($hasTunnel) {
    Write-Host 'Public Deployment Mode (Render FastAPI -> Host Machine):' -ForegroundColor Yellow
    Write-Host '  Render > vibesec-fastapi > Environment Variables:' -ForegroundColor Gray
    Write-Host '    OLLAMA_URL          : ' -NoNewline -ForegroundColor Gray
    Write-Host $url -ForegroundColor White
    Write-Host '    OLLAMA_PROXY_TOKEN  : ' -NoNewline -ForegroundColor Gray
    Write-Host "$maskedToken (Masked)" -ForegroundColor White
    if ($clipboardCopied) {
        Write-Host '  [Copied full token to Windows clipboard automatically]' -ForegroundColor Green
    }
    Write-Host ''
    Write-Host 'Keyboard Shortcuts:' -ForegroundColor Cyan
    Write-Host '  [T] Copy full OLLAMA_PROXY_TOKEN to clipboard' -ForegroundColor White
    Write-Host '  [U] Copy OLLAMA_URL to clipboard' -ForegroundColor White
    Write-Host '  [Q] Exit this monitor' -ForegroundColor White
} else {
    Write-Host 'Public Deployment Mode (Optional):' -ForegroundColor Yellow
    Write-Host '  Cloudflare Tunnel is currently offline or skipped.' -ForegroundColor Gray
    Write-Host '  Local application on http://localhost:3000 is unaffected and operational.' -ForegroundColor Green
    Write-Host '  To bridge to public Render: install cloudflared and run task "Start Remote AI Tunnel".' -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Keyboard Shortcuts:' -ForegroundColor Cyan
    if ($token) {
        Write-Host '  [T] Copy proxy token to clipboard' -ForegroundColor White
    }
    Write-Host '  [Q] Exit this monitor' -ForegroundColor White
}

Write-Host ''
Write-Host '[READY] Connection details are displayed above.' -ForegroundColor Green

while ($true) {
    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true).Key
        if ($key -eq [ConsoleKey]::T) {
            try {
                Set-Clipboard -Value $token
                Write-Host "`n[COPIED] OLLAMA_PROXY_TOKEN copied to clipboard!" -ForegroundColor Green
            } catch {}
        } elseif ($key -eq [ConsoleKey]::U) {
            try {
                Set-Clipboard -Value $url
                Write-Host "`n[COPIED] OLLAMA_URL copied to clipboard!" -ForegroundColor Green
            } catch {}
        } elseif ($key -eq [ConsoleKey]::Q) {
            break
        }
    }
    Start-Sleep -Milliseconds 250
}
