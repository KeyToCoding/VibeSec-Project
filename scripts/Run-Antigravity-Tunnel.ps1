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

# Ensure token exists or initialize
if (-not (Test-Path $TokenFile)) {
    $newToken = [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 })).ToLower()
    Set-Content -Path $TokenFile -Value $newToken -Encoding ASCII -NoNewline
}
$token = (Get-Content $TokenFile -Raw).Trim()

$proxyReady = $false
for ($i = 0; $i -lt 120; $i++) {
    if (Test-AuthenticatedProxy $token) { $proxyReady = $true; break }
    if ($i -eq 0) { Write-Host '[WAIT] Waiting for authenticated proxy at 127.0.0.1:11435...' -ForegroundColor Yellow }
    Start-Sleep -Seconds 1
}
if (-not $proxyReady) {
    Write-Host '[WARN] Authenticated proxy on port 11435 did not respond. Tunnel cannot forward traffic.' -ForegroundColor Yellow
    Write-Host '[INFO] Local mode operates normally via direct connection (http://127.0.0.1:11434).' -ForegroundColor Gray
    Write-Host '[READY] Local mode active - Cloudflare tunnel skipped (authenticated proxy offline).' -ForegroundColor Green
    while ($true) { Start-Sleep -Seconds 60 }
}

$cloudflared = Find-Cloudflared
if (-not $cloudflared) {
    Write-Host '[WARN] cloudflared.exe was not found on PATH or Program Files.' -ForegroundColor Yellow
    Write-Host '[INFO] Local VibeSec operates independently of Cloudflare.' -ForegroundColor Gray
    Write-Host '[INFO] To enable remote AI for public Render deployment, install cloudflared: winget install Cloudflare.cloudflared' -ForegroundColor Cyan
    Write-Host '[READY] Local mode active - Cloudflare tunnel skipped (cloudflared not installed).' -ForegroundColor Green
    while ($true) { Start-Sleep -Seconds 60 }
}

try {
    $oldTunnels = @(Get-CimInstance Win32_Process -Filter "Name='cloudflared.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '127\.0\.0\.1:11435' })
} catch { $oldTunnels = @() }
if ($oldTunnels.Count -gt 0) {
    Write-Host '[INFO] Existing Cloudflare tunnel detected on port 11435; reusing active process.' -ForegroundColor Green
    if (Test-Path $UrlFile) {
        $existingUrl = (Get-Content $UrlFile -Raw).Trim()
        Write-Host "[READY] Cloudflare tunnel URL: $existingUrl" -ForegroundColor Green
        while ($true) { Start-Sleep -Seconds 30 }
    }
}

foreach ($file in @($UrlFile, $StdOutFile, $StdErrFile)) { if (Test-Path $file) { Remove-Item $file -Force } }
New-Item -ItemType File -Path $StdOutFile -Force | Out-Null
New-Item -ItemType File -Path $StdErrFile -Force | Out-Null

$process = $null
$seenOut = 0
$seenErr = 0
$tunnelUrl = $null
$startedAt = Get-Date
Write-Host '[INFO] Starting cloudflared with output redirected to local logs...' -ForegroundColor Gray
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
                        Set-Content -LiteralPath (Join-Path $PSScriptRoot '.tunnel_url') -Value $tunnelUrl -Encoding ASCII -NoNewline
                        Write-Host "[READY] Cloudflare tunnel URL: $tunnelUrl" -ForegroundColor Green
                    }
                }
            }
            if ($item.Stream -eq 'OUT') { $seenOut = $lines.Count } else { $seenErr = $lines.Count }
        }
        if (-not $tunnelUrl -and ((Get-Date) - $startedAt).TotalSeconds -gt 90) {
            Write-Host '[WARN] Cloudflare URL was not detected within 90 seconds. Checking logs...' -ForegroundColor Yellow
            break
        }
        Start-Sleep -Milliseconds 400
        $process.Refresh()
    }

    # Flush any final output
    foreach ($item in @(@{ Path = $StdOutFile; Stream = 'OUT'; Seen = $seenOut }, @{ Path = $StdErrFile; Stream = 'ERR'; Seen = $seenErr })) {
        $lines = @(Get-Content -LiteralPath $item.Path -ErrorAction SilentlyContinue)
        for ($index = [int]$item.Seen; $index -lt $lines.Count; $index++) {
            $line = [string]$lines[$index]
            if ($line) { Write-Host ("[cloudflared {0}] {1}" -f $item.Stream, $line) -ForegroundColor DarkGray }
            if (-not $tunnelUrl -and $line -match 'https://[a-zA-Z0-9-]+\.trycloudflare\.com') {
                $tunnelUrl = $Matches[0]
                Set-Content -LiteralPath $UrlFile -Value $tunnelUrl -Encoding ASCII -NoNewline
                Set-Content -LiteralPath (Join-Path $PSScriptRoot '.tunnel_url') -Value $tunnelUrl -Encoding ASCII -NoNewline
                Write-Host "[READY] Cloudflare tunnel URL: $tunnelUrl" -ForegroundColor Green
            }
        }
    }

    while ($true) { Start-Sleep -Seconds 60 }
}
finally {
    if ($process -and -not $process.HasExited) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}
