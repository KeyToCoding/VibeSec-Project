# Start-Ollama-Proxy.ps1
# Starts the VibeSec Authenticated Ollama Proxy for Cloudflare Tunnel Zero-Cost Deployment
[CmdletBinding()]
param(
    [string]$Token = $env:OLLAMA_PROXY_TOKEN,
    [int]$Port = 11435,
    [string]$Target = "http://127.0.0.1:11434",
    [switch]$RotateToken
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $ProjectRoot "vibesec\backend"
$TokenFile = Join-Path $PSScriptRoot ".proxy_token"
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

# 3. Resolve, persist, or rotate OLLAMA_PROXY_TOKEN
if ($RotateToken) {
    Write-Host "`n[*] Token rotation requested (-RotateToken)..." -ForegroundColor Yellow
    $Token = $null
}

if (-not $Token -and (Test-Path $TokenFile)) {
    $existing = (Get-Content $TokenFile -Raw).Trim()
    if ($existing.Length -ge 16) {
        $Token = $existing
        Write-Host "[OK] Loaded existing OLLAMA_PROXY_TOKEN from $TokenFile" -ForegroundColor Green
    }
}

if (-not $Token) {
    # Check backend .env
    $envFile = Join-Path $BackendDir ".env"
    if (Test-Path $envFile) {
        $envMatch = Get-Content $envFile | Select-String "^OLLAMA_PROXY_TOKEN=(.+)$"
        if ($envMatch) {
            $Token = $envMatch.Matches[0].Groups[1].Value.Trim()
            Write-Host "[OK] Loaded OLLAMA_PROXY_TOKEN from backend .env" -ForegroundColor Green
        }
    }
}

if (-not $Token) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Token = -join ($bytes | ForEach-Object { "{0:x2}" -f $_ })
    # Securely persist token to local ignored file
    Set-Content -Path $TokenFile -Value $Token -Encoding UTF8 -Force
    Write-Host "`n[!] Generated new persistent OLLAMA_PROXY_TOKEN and saved to scripts/.proxy_token" -ForegroundColor Yellow
    Write-Host "    Masked Token: $($Token.Substring(0, 4))...$($Token.Substring($Token.Length - 4))" -ForegroundColor Gray
    Write-Host "    (Configure this token in your Render FastAPI environment variables: OLLAMA_PROXY_TOKEN)" -ForegroundColor Gray
} else {
    # Ensure saved to token file for consistency
    if (-not (Test-Path $TokenFile)) {
        Set-Content -Path $TokenFile -Value $Token -Encoding UTF8 -Force
    }
    Write-Host "[OK] Using configured OLLAMA_PROXY_TOKEN: $($Token.Substring(0, 4))...$($Token.Substring($Token.Length - 4))" -ForegroundColor Green
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
