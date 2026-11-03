$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$LogsDir = Join-Path $ProjectRoot 'logs'
$TokenFile = Join-Path $PSScriptRoot '.proxy_token'
$UrlFile = Join-Path $LogsDir 'cloudflare-url.txt'
$StdOutFile = Join-Path $LogsDir 'cloudflared-antigravity.stdout.log'
$StdErrFile = Join-Path $LogsDir 'cloudflared-antigravity.stderr.log'
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
Set-Location $ProjectRoot

function Test-AuthenticatedProxy([string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    try {
        $headers = @{ Authorization = "Bearer $Token" }
        $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/tags' -Headers $headers -TimeoutSec 4 -ErrorAction Stop
        return $true
    } catch { return $false }
}
function Find-Cloudflared {
    $cmd = Get-Command 'cloudflared.exe' -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command 'cloudflared' -ErrorAction SilentlyContinue }
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'cloudflared\cloudflared.exe'),
        (Join-Path $env:ProgramFiles 'cloudflared\cloudflared.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\cloudflared.exe')
    )
    foreach ($candidate in $candidates) { if ($candidate -and (Test-Path $candidate)) { return $candidate } }
    return $null
}

Write-Host '[START] VibeSec Cloudflare Quick Tunnel terminal' -ForegroundColor Cyan
if (-not (Test-Path $TokenFile)) { throw 'Missing scripts/.proxy_token. Start the authenticated proxy first.' }
$token = (Get-Content $TokenFile -Raw).Trim()
$proxyReady = $false
for ($i = 0; $i -lt 120; $i++) {
    if (Test-AuthenticatedProxy $token) { $proxyReady = $true; break }
    if ($i -eq 0) { Write-Host '[WAIT] Waiting for authenticated proxy at 127.0.0.1:11435...' -ForegroundColor Yellow }
    Start-Sleep -Seconds 1
}
if (-not $proxyReady) { throw 'Authenticated proxy did not become ready within 120 seconds.' }

$cloudflared = Find-Cloudflared
if (-not $cloudflared) { throw 'cloudflared.exe was not found. Install cloudflared or add it to PATH.' }
try {
    $oldTunnels = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '127\.0\.0\.1:11435' })
} catch { $oldTunnels = @() }
if ($oldTunnels.Count -gt 0) {
    throw 'An older Cloudflare tunnel for port 11435 is already running. Stop that tunnel with Ctrl+C in its old terminal, then rerun Start All.'
}

foreach ($file in @($UrlFile, $StdOutFile, $StdErrFile)) { if (Test-Path $file) { Remove-Item $file -Force } }
New-Item -ItemType File -Path $StdOutFile -Force | Out-Null
New-Item -ItemType File -Path $StdErrFile -Force | Out-Null

$process = $null
$seenOut = 0
$seenErr = 0
$tunnelUrl = $null
$startedAt = Get-Date
Write-Host '[INFO] Starting cloudflared with output redirected to local log files (no PowerShell stderr pipeline).' -ForegroundColor Gray
try {
    $process = Start-Process -FilePath $cloudflared -ArgumentList @('tunnel', '--url', 'http://127.0.0.1:11435') -WorkingDirectory $ProjectRoot -WindowStyle Hidden -RedirectStandardOutput $StdOutFile -RedirectStandardError $StdErrFile -PassThru

    while (-not $process.HasExited) {
        foreach ($item in @(@{ Path = $StdOutFile; Stream = 'OUT'; Seen = $seenOut }, @{ Path = $StdErrFile; Stream = 'ERR'; Seen = $seenErr })) {
            $lines = @(Get-Content -LiteralPath $item.Path -ErrorAction SilentlyContinue)
            for ($index = [int]$item.Seen; $index -lt $lines.Count; $index++) {
                $line = [string]$lines[$index]
                if ($line) {
                    Write-Host ("[cloudflared {0}] {1}" -f $item.Stream, $line) -ForegroundColor DarkGray
                    if (-not $tunnelUrl -and $line -match 'https://[a-zA-Z0-9-]+\.trycloudflare\.com') {
                        $tunnelUrl = $Matches[0]
                        Set-Content -LiteralPath $UrlFile -Value $tunnelUrl -Encoding ASCII -NoNewline
                        Write-Host "[READY] Cloudflare tunnel URL: $tunnelUrl" -ForegroundColor Green
                    }
                }
            }
            if ($item.Stream -eq 'OUT') { $seenOut = $lines.Count } else { $seenErr = $lines.Count }
        }
        if (-not $tunnelUrl -and ((Get-Date) - $startedAt).TotalSeconds -gt 90) {
            throw 'Cloudflare URL was not detected within 90 seconds. Review logs/cloudflared-antigravity.stderr.log.'
        }
        Start-Sleep -Milliseconds 400
        $process.Refresh()
    }

    # Flush any final output after the process exits.
    foreach ($item in @(@{ Path = $StdOutFile; Stream = 'OUT'; Seen = $seenOut }, @{ Path = $StdErrFile; Stream = 'ERR'; Seen = $seenErr })) {
        $lines = @(Get-Content -LiteralPath $item.Path -ErrorAction SilentlyContinue)
        for ($index = [int]$item.Seen; $index -lt $lines.Count; $index++) {
            $line = [string]$lines[$index]
            if ($line) { Write-Host ("[cloudflared {0}] {1}" -f $item.Stream, $line) -ForegroundColor DarkGray }
            if (-not $tunnelUrl -and $line -match 'https://[a-zA-Z0-9-]+\.trycloudflare\.com') {
                $tunnelUrl = $Matches[0]
                Set-Content -LiteralPath $UrlFile -Value $tunnelUrl -Encoding ASCII -NoNewline
                Write-Host "[READY] Cloudflare tunnel URL: $tunnelUrl" -ForegroundColor Green
            }
        }
    }
    if ($process.ExitCode -ne 0) { throw "cloudflared exited with code $($process.ExitCode). Review logs/cloudflared-antigravity.stderr.log." }
    throw 'cloudflared exited unexpectedly.'
}
finally {
    if ($process -and -not $process.HasExited) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}
