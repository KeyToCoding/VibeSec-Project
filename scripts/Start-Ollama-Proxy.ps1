# Start-Ollama-Proxy.ps1
# Starts the VibeSec Authenticated Ollama Proxy for Cloudflare Tunnel Zero-Cost Deployment
[CmdletBinding()]
param(
    [string]$Token = $env:OLLAMA_PROXY_TOKEN,
    [int]$Port = 11435,
    [string]$Target = "http://127.0.0.1:11434"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $ProjectRoot "vibesec\backend"
$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
$ProxyScript = Join-Path $ProjectRoot "scripts\ollama_proxy.py"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "     VibeSec Authenticated Ollama Proxy Launcher    " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Resolve Python executable
$PythonExe = "python"
if (Test-Path $VenvPython) {
    $PythonExe = $VenvPython
    Write-Host "[OK] Using backend virtualenv Python: $PythonExe" -ForegroundColor Green
} else {
    Write-Host "[*] Using system Python: $(Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)" -ForegroundColor Yellow
}

# 2. Check local Ollama status
Write-Host "`n[*] Verifying local Ollama service at $Target..." -ForegroundColor Yellow
try {
    $resp = Invoke-RestMethod -Uri "$Target/api/tags" -Method Get -TimeoutSec 3 -ErrorAction Stop
    $modelList = ($resp.models | ForEach-Object { $_.name }) -join ", "
    Write-Host "[OK] Local Ollama is online. Available models: $modelList" -ForegroundColor Green
} catch {
    Write-Host "[!] Local Ollama is NOT responding at $Target." -ForegroundColor DarkYellow
    Write-Host "    Make sure to start Ollama in another terminal: 'ollama serve'" -ForegroundColor Gray
}

# 3. Resolve or generate OLLAMA_PROXY_TOKEN
if (-not $Token) {
    # Check backend .env
    $envFile = Join-Path $BackendDir ".env"
    if (Test-Path $envFile) {
        $envMatch = Get-Content $envFile | Select-String "^OLLAMA_PROXY_TOKEN=(.+)$"
        if ($envMatch) {
            $Token = $envMatch.Matches[0].Groups[1].Value.Trim()
        }
    }
}

if (-not $Token) {
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Token = -join ($bytes | ForEach-Object { "{0:x2}" -f $_ })
    Write-Host "`n[!] Generated new secure OLLAMA_PROXY_TOKEN: $Token" -ForegroundColor Yellow
    Write-Host "    Add this to your Render FastAPI environment variables: OLLAMA_PROXY_TOKEN=$Token" -ForegroundColor Gray
} else {
    Write-Host "`n[OK] Using configured OLLAMA_PROXY_TOKEN." -ForegroundColor Green
}

# 4. Check for cloudflared
Write-Host "`n[*] Checking Cloudflare Tunnel (cloudflared)..." -ForegroundColor Yellow
$cloudflaredCmd = Get-Command cloudflared -ErrorAction SilentlyContinue
if ($cloudflaredCmd) {
    Write-Host "[OK] cloudflared found at: $($cloudflaredCmd.Source)" -ForegroundColor Green
    Write-Host "`nTo create a free zero-cost public tunnel to this proxy, run in a separate terminal:" -ForegroundColor Cyan
    Write-Host "  cloudflared tunnel --url http://127.0.0.1:$Port" -ForegroundColor White
} else {
    Write-Host "[!] cloudflared not found on PATH." -ForegroundColor Gray
    Write-Host "    Download the free standalone executable from: https://github.com/cloudflare/cloudflared/releases" -ForegroundColor Gray
    Write-Host "    Then run: cloudflared.exe tunnel --url http://127.0.0.1:$Port" -ForegroundColor Gray
}

Write-Host "`n[*] Starting proxy listener on http://127.0.0.1:$Port forwarding to $Target..." -ForegroundColor Cyan
& "$PythonExe" "$ProxyScript" --host "127.0.0.1" --port $Port --target "$Target" --token "$Token"
