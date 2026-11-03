$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$TokenFile = Join-Path $PSScriptRoot '.proxy_token'
$ProxyLauncher = Join-Path $PSScriptRoot 'Start-Ollama-Proxy.ps1'
Set-Location $ProjectRoot

function Test-OllamaReady {
    try { $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3 -ErrorAction Stop; return $true }
    catch { return $false }
}
function Test-PortListening([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $result = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        $connected = $result.AsyncWaitHandle.WaitOne(800)
        if ($connected -and $client.Connected) { $client.EndConnect($result); return $true }
        return $false
    } catch { return $false } finally { $client.Close() }
}
function Test-AuthenticatedProxy([string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    try {
        $headers = @{ Authorization = "Bearer $Token" }
        $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/tags' -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        return $true
    } catch { return $false }
}

Write-Host '[START] VibeSec authenticated Ollama proxy terminal' -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 120; $i++) {
    if (Test-OllamaReady) { $ready = $true; break }
    if ($i -eq 0) { Write-Host '[WAIT] Waiting for Ollama at 127.0.0.1:11434...' -ForegroundColor Yellow }
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw 'Ollama did not become ready within 120 seconds. Check the Ollama terminal.' }
if (-not (Test-Path $TokenFile)) { throw 'scripts/.proxy_token is missing. Run scripts/Start-Ollama-Proxy.ps1 once to create the persistent token.' }
$token = (Get-Content $TokenFile -Raw).Trim()
if ($token.Length -lt 16) { throw 'scripts/.proxy_token is empty or invalid. Do not paste the token into chat.' }

if (Test-AuthenticatedProxy $token) {
    Write-Host '[READY] Authenticated Ollama proxy is already running on 127.0.0.1:11435.' -ForegroundColor Green
    Write-Host 'Reusing the existing proxy; no duplicate listener will be started.' -ForegroundColor Gray
    while (Test-AuthenticatedProxy $token) { Start-Sleep -Seconds 10 }
    throw 'The existing authenticated proxy stopped responding.'
}
if (Test-PortListening 11435) { throw 'Port 11435 is occupied by a different process or a proxy using another token. Stop the old proxy terminal and rerun Start All.' }
if (-not (Test-Path $ProxyLauncher)) { throw "Existing proxy launcher not found: $ProxyLauncher" }
Write-Host '[INFO] Starting the existing authenticated proxy script in this Antigravity terminal...' -ForegroundColor Yellow
& $ProxyLauncher
if ($LASTEXITCODE -ne 0) { throw "Proxy launcher exited with code $LASTEXITCODE" }
