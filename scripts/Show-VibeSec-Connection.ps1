[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TunnelUrl
)

$ErrorActionPreference = 'Stop'
$TokenFile = Join-Path $PSScriptRoot '.proxy_token'
$CleanUrl = $TunnelUrl.Trim().TrimEnd('/')
if (-not (Test-Path $TokenFile)) { throw "Token file not found: $TokenFile. Start the authenticated proxy first." }
$Token = (Get-Content $TokenFile -Raw).Trim()
if ($Token.Length -lt 16) { throw 'The saved proxy token is missing or invalid.' }
$Masked = if ($Token.Length -ge 8) { $Token.Substring(0,4) + '...' + $Token.Substring($Token.Length - 4) } else { '********' }

Clear-Host
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '          VibeSec — Render Connection Details' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "OLLAMA_URL         : $CleanUrl" -ForegroundColor White
Write-Host "OLLAMA_PROXY_TOKEN: $Masked (hidden)" -ForegroundColor Yellow
Write-Host ''
Write-Host 'Use these values in Render > vibesec-fastapi > Environment.' -ForegroundColor Gray
Write-Host 'The token is NEVER printed in full. Choose T to copy it directly to clipboard.' -ForegroundColor Gray
Write-Host 'Do not paste the token into chat, screenshots, source files, or GitHub.' -ForegroundColor Yellow
Write-Host '------------------------------------------------------------' -ForegroundColor Cyan

while ($true) {
    $choice = Read-Host '[U] Copy OLLAMA_URL   [T] Copy token   [Q] Quit this details window'
    switch ($choice.Trim().ToUpperInvariant()) {
        'U' {
            Set-Clipboard -Value $CleanUrl
            Write-Host '[OK] OLLAMA_URL copied to clipboard.' -ForegroundColor Green
        }
        'T' {
            Set-Clipboard -Value $Token
            Write-Host '[OK] OLLAMA_PROXY_TOKEN copied to clipboard. Full token was not displayed.' -ForegroundColor Green
        }
        'Q' { break }
        default { Write-Host 'Choose U, T, or Q.' -ForegroundColor Yellow }
    }
}
