$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$LogsDir = Join-Path $ProjectRoot 'logs'
$LogFile = Join-Path $LogsDir 'ollama-antigravity.log'
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
Set-Location $ProjectRoot

function Test-OllamaReady {
    try {
        $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3 -ErrorAction Stop
        return $true
    } catch { return $false }
}

Write-Host '[START] VibeSec Ollama terminal' -ForegroundColor Cyan
# Give an already-starting Ollama desktop process a moment before starting a server ourselves.
for ($i = 0; $i -lt 10; $i++) {
    if (Test-OllamaReady) { break }
    Start-Sleep -Seconds 1
}

if (-not (Test-OllamaReady)) {
    $ollamaCommand = Get-Command 'ollama.exe' -ErrorAction SilentlyContinue
    if (-not $ollamaCommand) { $ollamaCommand = Get-Command 'ollama' -ErrorAction SilentlyContinue }
    if ($ollamaCommand) { $ollamaPath = $ollamaCommand.Source }
    else {
        $candidate = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
        if (Test-Path $candidate) { $ollamaPath = $candidate }
        else { throw 'Ollama is not responding and ollama.exe was not found. Start the Ollama Windows app, then run the VibeSec tasks again.' }
    }

    Write-Host '[INFO] Ollama is offline. Starting ollama serve without opening another console window...' -ForegroundColor Yellow
    $ollamaOut = Join-Path $LogsDir 'ollama-antigravity.stdout.log'
    $ollamaErr = Join-Path $LogsDir 'ollama-antigravity.stderr.log'
    foreach ($file in @($ollamaOut, $ollamaErr)) { if (Test-Path $file) { Remove-Item $file -Force } }
    New-Item -ItemType File -Path $ollamaOut -Force | Out-Null
    New-Item -ItemType File -Path $ollamaErr -Force | Out-Null
    $ollamaProcess = Start-Process -FilePath $ollamaPath -ArgumentList 'serve' -WindowStyle Hidden -WorkingDirectory $ProjectRoot -RedirectStandardOutput $ollamaOut -RedirectStandardError $ollamaErr -PassThru
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-OllamaReady) { $ready = $true; break }
        if ($ollamaProcess.HasExited) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Ollama did not become ready. Check logs/ollama-antigravity.stderr.log.' }
}

Write-Host '[READY] Ollama is responding at http://127.0.0.1:11434' -ForegroundColor Green
try {
    $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 5
    Write-Host 'Model inventory:' -ForegroundColor Gray
    $tags.models | ForEach-Object { Write-Host ("  - " + $_.name) -ForegroundColor White }
} catch {}
Write-Host 'This terminal is monitoring Ollama. Press Ctrl+C here only when you want to stop this monitor.' -ForegroundColor Yellow
while ($true) {
    Start-Sleep -Seconds 15
    if (-not (Test-OllamaReady)) {
        Write-Host '[WARN] Ollama stopped responding. Start/restart the Ollama Windows app or run ollama serve.' -ForegroundColor Yellow
    }
}
