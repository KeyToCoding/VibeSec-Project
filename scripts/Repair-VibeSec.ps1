# Repair-VibeSec.ps1
# Diagnostics and self-repair for VibeSec
[CmdletBinding()]
param(
    [switch]$ForceReinstall = $false,
    [switch]$SkipTests = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $ProjectRoot "vibesec\backend"
$VenvDir = Join-Path $BackendDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$SemgrepDir = Join-Path $BackendDir ".semgrep-env"
$SemgrepPython = Join-Path $SemgrepDir "Scripts\python.exe"
$ReqFile = Join-Path $BackendDir "requirements.txt"
$LogsDir = Join-Path $ProjectRoot "logs"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "          VibeSec Diagnostic & Repair Tool         " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot" -ForegroundColor Gray
Write-Host "Backend Path : $BackendDir" -ForegroundColor Gray

# 1. Logs directory
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    Write-Host "[OK] Created logs directory: $LogsDir" -ForegroundColor Green
} else {
    Write-Host "[OK] Logs directory present." -ForegroundColor Green
}

# 2. Check Backend Virtual Environment
Write-Host "`n[1/6] Checking Backend Python Environment (.venv)..." -ForegroundColor Yellow
if (-not (Test-Path $VenvPython)) {
    Write-Host "[!] Backend .venv missing. Creating virtual environment at $VenvDir..." -ForegroundColor Yellow
    python -m venv "$VenvDir"
    if (-not (Test-Path $VenvPython)) {
        Write-Error "Failed to create virtual environment at $VenvDir. Ensure python is installed."
        exit 1
    }
}
Write-Host "[OK] Python executable found: $VenvPython" -ForegroundColor Green

# Clean up broken pip temp directories (~ydantic, etc.)
$SitePackages = Join-Path $VenvDir "Lib\site-packages"
if (Test-Path $SitePackages) {
    Get-ChildItem -Path $SitePackages -Filter "~*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "[!] Removing corrupt temporary package directory: $($_.FullName)" -ForegroundColor Yellow
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Check requirements
$NeedInstall = $ForceReinstall
if (-not $NeedInstall) {
    $TestImport = & "$VenvPython" -c "import fastapi, uvicorn, pydantic, httpx, dotenv, requests, jwt; print('OK')" 2>$null
    if ($TestImport -ne "OK") {
        Write-Host "[!] Backend missing one or more dependencies. Triggering install..." -ForegroundColor Yellow
        $NeedInstall = $true
    }
}

if ($NeedInstall) {
    Write-Host "[*] Installing/updating requirements from $ReqFile..." -ForegroundColor Cyan
    & "$VenvPython" -m pip install --upgrade pip --quiet
    & "$VenvPython" -m pip install -r "$ReqFile" --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Error "pip install failed with code $LASTEXITCODE."
        exit $LASTEXITCODE
    }
    Write-Host "[OK] Backend dependencies installed." -ForegroundColor Green
} else {
    Write-Host "[OK] All core backend dependencies verified (fastapi, uvicorn, pydantic, httpx, etc.)." -ForegroundColor Green
}

# 3. Check Semgrep Environment & Executable Handling
Write-Host "`n[2/6] Checking Semgrep Environment..." -ForegroundColor Yellow
if (Test-Path $SemgrepPython) {
    Write-Host "[OK] Dedicated Semgrep Python environment detected: $SemgrepPython" -ForegroundColor Green
} else {
    Write-Host "[i] Dedicated Semgrep env not found at $SemgrepDir (native AST scanner fallback active)." -ForegroundColor Gray
}

# Ensure semgrep.cmd wrapper exists to prevent Windows "Open with" app selection dialog
$SemgrepScriptsDir = Join-Path $SemgrepDir "Scripts"
if (Test-Path $SemgrepScriptsDir) {
    $SemgrepCmd = Join-Path $SemgrepScriptsDir "semgrep.cmd"
    if (-not (Test-Path $SemgrepCmd)) {
        $CmdContent = "@echo off`r`n`"%~dp0python.exe`" -m semgrep %*`r`n"
        [System.IO.File]::WriteAllText($SemgrepCmd, $CmdContent)
        Write-Host "[OK] Created safe wrapper: $SemgrepCmd" -ForegroundColor Green
    }
}

# 4. Check Node.js & Frontend Environment
Write-Host "`n[3/6] Checking Frontend Environment..." -ForegroundColor Yellow
$NodeVersion = $null
try {
    $NodeVersion = node -v 2>$null
} catch {}

if (-not $NodeVersion) {
    Write-Error "Node.js is not found in PATH! Please install Node.js (v18+) to run the frontend."
    exit 1
}
Write-Host "[OK] Node.js version: $NodeVersion" -ForegroundColor Green

$NodeModules = Join-Path $ProjectRoot "node_modules"
if (-not (Test-Path $NodeModules)) {
    Write-Host "[*] node_modules missing. Running npm install..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    npm install
    Pop-Location
} else {
    Write-Host "[OK] node_modules present." -ForegroundColor Green
}

# 5. Check Local Ollama Service
Write-Host "`n[4/6] Checking Ollama Service..." -ForegroundColor Yellow
$OllamaUrl = "http://127.0.0.1:11434"
$OllamaAvailable = $false
try {
    $Response = Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -Method Get -TimeoutSec 3 -ErrorAction Stop
    $OllamaAvailable = $true
    Write-Host "[OK] Ollama is reachable at $OllamaUrl" -ForegroundColor Green

    $ModelFound = $false
    if ($Response.models) {
        $ModelNames = $Response.models | ForEach-Object { $_.name }
        if ($ModelNames -contains "qwen2.5-coder:7b" -or ($ModelNames | Where-Object { $_ -like "qwen2.5-coder*" })) {
            $ModelFound = $true
            Write-Host "[OK] Model 'qwen2.5-coder:7b' is present in Ollama." -ForegroundColor Green
        } else {
            Write-Host "[!] 'qwen2.5-coder:7b' not found in Ollama models: $($ModelNames -join ', ')" -ForegroundColor Yellow
            Write-Host "    To pull the recommended model, run: ollama pull qwen2.5-coder:7b" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "[!] Ollama is not responding at $OllamaUrl" -ForegroundColor Yellow
    Write-Host "    Make sure Ollama is running ('ollama serve' or open Ollama app) for AI remediation/chat." -ForegroundColor Gray
}

# 6. Verification and Health Checks
if (-not $SkipTests) {
    Write-Host "`n[5/6] Running Backend Tests (.venv)..." -ForegroundColor Yellow
    Push-Location $BackendDir
    & "$VenvPython" -m unittest discover -s "tests" -p "test_*.py"
    $TestExitCode = $LASTEXITCODE
    Pop-Location
    if ($TestExitCode -ne 0) {
        Write-Error "Backend unit tests failed! Inspect errors above."
        exit $TestExitCode
    }
    Write-Host "[OK] Backend unit & integration tests passed." -ForegroundColor Green

    Write-Host "`n[6/6] Verifying Frontend TypeScript..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    npm run lint
    $LintExitCode = $LASTEXITCODE
    Pop-Location
    if ($LintExitCode -ne 0) {
        Write-Error "Frontend typecheck failed."
        exit $LintExitCode
    }
    Write-Host "[OK] Frontend TypeScript check passed with 0 errors." -ForegroundColor Green
}

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "   VibeSec Environment Repaired and Verified!      " -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Next steps:" -ForegroundColor Gray
Write-Host "  To launch: .\scripts\Start-VibeSec.ps1" -ForegroundColor Cyan
Write-Host "  To stop:   .\scripts\Stop-VibeSec.ps1" -ForegroundColor Cyan
