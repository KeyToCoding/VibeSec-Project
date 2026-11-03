# Repair-Venv.ps1
# Detects compatible Python installation and recreates vibesec/backend/.venv safely
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $ProjectRoot "vibesec\backend"
$VenvDir = Join-Path $BackendDir ".venv"
$ReqFile = Join-Path $BackendDir "requirements.txt"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "     VibeSec Python Virtual Environment Repair      " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Check for compatible Python executable
$CandidatePythons = @()

# Check py launcher
$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pyLauncher) {
    try {
        $pyList = & py -0 2>$null
        Write-Host "[*] Python launcher detected installations:" -ForegroundColor Gray
        $pyList | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    } catch {}
}

# Check system python
$sysPython = Get-Command python -ErrorAction SilentlyContinue
if ($sysPython) {
    $ver = & python --version 2>&1
    Write-Host "[*] System python: $($sysPython.Source) ($ver)" -ForegroundColor Green
    $CandidatePythons += $sysPython.Source
}

# Check common AppData / Program Files paths
$commonPaths = @(
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python314\python.exe"
)
foreach ($p in $commonPaths) {
    if (Test-Path $p) {
        $CandidatePythons += $p
    }
}

if ($CandidatePythons.Count -eq 0) {
    Write-Host "[ERROR] No compatible Python installation found on system." -ForegroundColor Red
    Write-Host "        Please install Python 3.11 or 3.12 from python.org or Windows Store." -ForegroundColor Yellow
    exit 1
}

$SelectedPython = $CandidatePythons[0]
Write-Host "`n[*] Selected base Python: $SelectedPython" -ForegroundColor Green

# 2. Inspect existing .venv
$NeedsRecreate = $Force
if (Test-Path $VenvDir) {
    $cfgPath = Join-Path $VenvDir "pyvenv.cfg"
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw
        $homeMatch = $cfg | Select-String "home\s*=\s*(.+)"
        if ($homeMatch) {
            $baseHome = $homeMatch.Matches[0].Groups[1].Value.Trim()
            $baseExe = Join-Path $baseHome "python.exe"
            if (-not (Test-Path $baseExe)) {
                Write-Host "[!] Existing .venv points to missing base Python: $baseExe" -ForegroundColor Yellow
                $NeedsRecreate = $true
            } else {
                Write-Host "[OK] Existing .venv base Python exists: $baseExe" -ForegroundColor Green
            }
        }
    } else {
        $NeedsRecreate = $true
    }
} else {
    $NeedsRecreate = $true
}

# 3. Recreate if broken or requested
if ($NeedsRecreate) {
    Write-Host "`n[*] Recreating virtual environment at $VenvDir..." -ForegroundColor Yellow
    if (Test-Path $VenvDir) {
        Remove-Item -Path $VenvDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    & "$SelectedPython" -m venv "$VenvDir"
    Write-Host "[OK] Created fresh virtual environment." -ForegroundColor Green

    $VenvPip = Join-Path $VenvDir "Scripts\pip.exe"
    if (Test-Path $ReqFile) {
        Write-Host "`n[*] Installing dependencies from $ReqFile..." -ForegroundColor Yellow
        & "$VenvPip" install --upgrade pip
        & "$VenvPip" install -r "$ReqFile"
        Write-Host "[OK] Dependencies installed successfully." -ForegroundColor Green
    }
} else {
    Write-Host "`n[OK] .venv is healthy. Use -Force if you wish to reinstall." -ForegroundColor Green
}

# 4. Verify .gitignore protection
$GitIgnore = Join-Path $ProjectRoot ".gitignore"
if (Test-Path $GitIgnore) {
    $gi = Get-Content $GitIgnore -Raw
    if ($gi -notmatch "\.venv/") {
        Add-Content -Path $GitIgnore -Value "`n.venv/`nvibesec/backend/.venv/"
        Write-Host "[OK] Ensured .venv is gitignored." -ForegroundColor Green
    }
}

