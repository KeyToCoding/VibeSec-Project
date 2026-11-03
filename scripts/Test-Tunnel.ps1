# Test-Tunnel.ps1
# Validates Cloudflare Tunnel connectivity and authenticated Ollama inference
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TunnelUrl,
    [string]$Token,
    [string]$Model = "qwen2.5-coder:7b"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$TokenFile = Join-Path $PSScriptRoot ".proxy_token"
$BackendEnv = Join-Path $ProjectRoot "vibesec\backend\.env"

if (-not $Token -and (Test-Path $TokenFile)) {
    $Token = (Get-Content $TokenFile -Raw).Trim()
}
if (-not $Token -and (Test-Path $BackendEnv)) {
    $m = Get-Content $BackendEnv | Select-String "^OLLAMA_PROXY_TOKEN=(.+)$"
    if ($m) { $Token = $m.Matches[0].Groups[1].Value.Trim() }
}
if (-not $Token) {
    $Token = $env:OLLAMA_PROXY_TOKEN
}

$CleanUrl = $TunnelUrl.Trim().TrimEnd("/")

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "     VibeSec Tunnel Diagnostic & Validation Tool    " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Target Tunnel: $CleanUrl" -ForegroundColor White

if (-not $Token) {
    Write-Host "[ERROR] No OLLAMA_PROXY_TOKEN found. Provide -Token or run Start-Ollama-Proxy.ps1 first." -ForegroundColor Red
    exit 1
}

$Masked = if ($Token.Length -ge 8) { "$($Token.Substring(0, 4))...$($Token.Substring($Token.Length - 4))" } else { "****" }
Write-Host "Using Token  : $Masked" -ForegroundColor Gray

# Step 1: Check Tunnel Reachability & Proxy Auth (/api/tags)
Write-Host "`n[1/2] Probing tunnel endpoint and authenticated model list..." -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $headers = @{
        "Authorization" = "Bearer $Token"
        "User-Agent" = "VibeSec-Tunnel-Validator/1.0"
    }
    $tagsResp = Invoke-RestMethod -Uri "$CleanUrl/api/tags" -Method Get -Headers $headers -TimeoutSec 15
    $sw.Stop()
    $modelNames = ($tagsResp.models | ForEach-Object { $_.name })
    Write-Host "[PASS] Tunnel responded in $($sw.ElapsedMilliseconds)ms (HTTP 200)" -ForegroundColor Green
    Write-Host "       Available models: $($modelNames -join ', ')" -ForegroundColor Gray

    if ($modelNames -notcontains $Model) {
        Write-Host "[WARN] Model '$Model' not listed in Ollama tags! Available: $($modelNames -join ', ')" -ForegroundColor DarkYellow
    }
} catch {
    $sw.Stop()
    Write-Host "[FAIL] Tunnel probe failed after $($sw.ElapsedMilliseconds)ms" -ForegroundColor Red
    if ($_.Exception.Response) {
        $status = [int]$_.Exception.Response.StatusCode
        Write-Host "       HTTP Status: $status" -ForegroundColor Red
        if ($status -eq 530) {
            Write-Host "       Diagnosis: Cloudflare Error 530 (Origin Down / Tunnel Not Connected)." -ForegroundColor Yellow
            Write-Host "                  Ensure 'cloudflared tunnel --url http://127.0.0.1:11435' is running." -ForegroundColor Yellow
        } elseif ($status -eq 401) {
            Write-Host "       Diagnosis: Authentication rejected. The token passed does not match OLLAMA_PROXY_TOKEN." -ForegroundColor Yellow
        } elseif ($status -eq 403) {
            Write-Host "       Diagnosis: Endpoint forbidden by proxy whitelist." -ForegroundColor Yellow
        }
    } else {
        Write-Host "       Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}

# Step 2: Test Live Authenticated Inference (/api/generate)
Write-Host "`n[2/2] Testing end-to-end model inference ($Model)..." -ForegroundColor Yellow
$sw.Restart()
try {
    $body = @{
        model = $Model
        prompt = "Reply with 'TUNNEL_VALIDATED' in one word."
        stream = $false
    } | ConvertTo-Json

    $inferResp = Invoke-RestMethod -Uri "$CleanUrl/api/generate" -Method Post -Headers $headers -Body $body -ContentType "application/json" -TimeoutSec 45
    $sw.Stop()
    $reply = $inferResp.response.Trim()
    Write-Host "[PASS] Model inference succeeded in $($sw.ElapsedMilliseconds)ms" -ForegroundColor Green
    Write-Host "       Model output: $reply" -ForegroundColor Gray

    Write-Host "`n====================================================" -ForegroundColor Green
    Write-Host " RESULT: TUNNEL IS HEALTHY AND READY FOR PRODUCTION!" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Green
    Write-Host "To connect production Render FastAPI to this tunnel, update:" -ForegroundColor White
    Write-Host "  Render FastAPI Environment: OLLAMA_URL = $CleanUrl" -ForegroundColor Cyan
    Write-Host "  Render FastAPI Environment: OLLAMA_PROXY_TOKEN = (configured token)" -ForegroundColor Cyan
} catch {
    $sw.Stop()
    Write-Host "[FAIL] Inference failed after $($sw.ElapsedMilliseconds)ms: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

