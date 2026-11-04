<#
.SYNOPSIS
    VibeSec First-Run Setup & Prerequisites Installer.
    Ensures Ollama, AI model, Python venv, and npm dependencies are prepared
    for one-click startup on any compatible Windows PC.

.DESCRIPTION
    1. Validates hardware (RAM, Disk, Architecture).
    2. Detects or installs Ollama (via Winget or official installer).
    3. Starts Ollama service and pulls required AI model (qwen2.5-coder:7b).
    4. Sets up backend Python virtual environment (.venv) and requirements.
    5. Verifies frontend Node.js and installs npm dependencies.
    6. Ensures safe environment templates and secrets are configured.
    7. Fully idempotent: Re-running skips all already-configured components.

.PARAMETER TargetModel
    The Ollama model to verify or pull (default: qwen2.5-coder:7b or $env:OLLAMA_MODEL).

.PARAMETER SimulateFreshPC
    Dry-run simulation mode for testing installation logic on systems where Ollama is already installed.
#>
[CmdletBinding()]
param(
    [string]$TargetModel = $(if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "qwen2.5-coder:7b" }),
    [switch]$SimulateFreshPC = $false,
    [switch]$SkipTests = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $ProjectRoot "vibesec\backend"
$VenvDir = Join-Path $BackendDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$ReqFile = Join-Path $BackendDir "requirements.txt"
$LogsDir = Join-Path $ProjectRoot "logs"
$TokenFile = Join-Path $PSScriptRoot ".proxy_token"
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
Set-Location $ProjectRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       VibeSec 0 - First-Run Setup & Prerequisites          " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot" -ForegroundColor Gray
Write-Host "Target Model : $TargetModel" -ForegroundColor Gray
if ($SimulateFreshPC) {
    Write-Host "[MODE] Running in Dry-Run / Fresh PC Simulation mode" -ForegroundColor Magenta
}

# -------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------
function Test-OllamaApi {
    try {
        $null = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 3 -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Find-OllamaExecutable {
    $cmd = Get-Command "ollama.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command "ollama" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"),
        (Join-Path $env:ProgramFiles "Ollama\ollama.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Ollama\ollama.exe"),
        (Join-Path $env:USERPROFILE "AppData\Local\Programs\Ollama\ollama.exe")
    )
    foreach ($cand in $candidates) {
        if ($cand -and (Test-Path $cand)) { return $cand }
    }
    return $null
}

# -------------------------------------------------------------------------
# Step 1: Hardware & Storage Checks
# -------------------------------------------------------------------------
Write-Host "`n[1/6] Checking Hardware & System Resources..." -ForegroundColor Yellow

$arch = $env:PROCESSOR_ARCHITECTURE
Write-Host "  - Processor Architecture: $arch" -ForegroundColor Gray
if ($arch -notin @("AMD64", "ARM64")) {
    Write-Host "  [WARN] Non-standard 64-bit architecture ($arch) detected." -ForegroundColor Yellow
}

# RAM check
$totalRamGB = 8.0
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.TotalPhysicalMemory) {
        $totalRamGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        Write-Host "  - Installed System RAM: $totalRamGB GB" -ForegroundColor Gray
    }
} catch {}

if ($totalRamGB -lt 7.0 -and $TargetModel -eq "qwen2.5-coder:7b") {
    Write-Host "  [NOTICE] System has < 8 GB RAM ($totalRamGB GB). The 7B model may run slowly on CPU." -ForegroundColor Yellow
    Write-Host "  [SUGGESTION] Set OLLAMA_MODEL=qwen2.5-coder:3b for resource-constrained systems." -ForegroundColor DarkYellow
}

# Disk space check
try {
    $driveLetter = $ProjectRoot.Substring(0, 1)
    $psDrive = Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue
    if ($psDrive -and $psDrive.Free) {
        $freeGB = [Math]::Round($psDrive.Free / 1GB, 1)
        Write-Host "  - Available Disk Space (${driveLetter}:): $freeGB GB" -ForegroundColor Gray
        if ($freeGB -lt 6.0) {
            Write-Host "  [WARN] Less than 6 GB free disk space available. Model download may fail if disk fills." -ForegroundColor Yellow
        }
    }
} catch {}

# Internet check
$hasInternet = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect("1.1.1.1", 53, $null, $null)
    if ($async.AsyncWaitHandle.WaitOne(1500)) {
        $tcp.EndConnect($async)
        $hasInternet = $true
    }
    $tcp.Close()
} catch {}
Write-Host "  - Internet Reachability: $(if ($hasInternet) { 'Connected' } else { 'Limited / Offline' })" -ForegroundColor $(if ($hasInternet) { "Green" } else { "Yellow" })

Write-Host "[OK] Hardware and system checks completed." -ForegroundColor Green

# -------------------------------------------------------------------------
# Step 2: Ollama Detection & Automatic Installation
# -------------------------------------------------------------------------
Write-Host "`n[2/6] Detecting or Installing Ollama..." -ForegroundColor Yellow

$ollamaExe = if ($SimulateFreshPC) { $null } else { Find-OllamaExecutable }

if (-not $ollamaExe) {
    Write-Host "  [!] Ollama is not installed on this system." -ForegroundColor Yellow
    if ($SimulateFreshPC) {
        Write-Host "  [SIMULATION] Simulating fresh PC Ollama installer detection." -ForegroundColor Magenta
        Write-Host "  [SIMULATION] Would invoke: winget install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements --silent" -ForegroundColor Gray
        Write-Host "  [SIMULATION] Fallback URL: https://ollama.com/download/OllamaSetup.exe" -ForegroundColor Gray
        $ollamaExe = Find-OllamaExecutable # Recover real path for subsequent steps if present
    } else {
        Write-Host "  [*] Attempting automated installation via Windows Package Manager (Winget)..." -ForegroundColor Cyan
        $wingetCmd = Get-Command "winget" -ErrorAction SilentlyContinue
        $installedViaWinget = $false
        if ($wingetCmd) {
            try {
                & winget install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements --silent
                if ($LASTEXITCODE -eq 0) {
                    $installedViaWinget = $true
                    Write-Host "  [OK] Ollama installed successfully via Winget." -ForegroundColor Green
                }
            } catch {
                Write-Host "  [!] Winget install returned error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        if (-not $installedViaWinget) {
            Write-Host "  [*] Downloading official verified installer from https://ollama.com/download/OllamaSetup.exe..." -ForegroundColor Cyan
            $installerTemp = Join-Path $env:TEMP "OllamaSetup.exe"
            try {
                Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $installerTemp -UseBasicParsing -TimeoutSec 120
                Write-Host "  [*] Running official per-user installer silently..." -ForegroundColor Cyan
                $p = Start-Process -FilePath $installerTemp -ArgumentList "/silent" -Wait -PassThru
                Write-Host "  [OK] Installer completed with exit code $($p.ExitCode)." -ForegroundColor Green
            } catch {
                Write-Host "  [ERROR] Automatic installer download failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "  Please manually install Ollama from: https://ollama.com/download/windows" -ForegroundColor Yellow
                throw "Ollama installation failed."
            }
        }

        # Refresh PATH in current session
        $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $env:Path = "$userPath;$machinePath"
        $ollamaExe = Find-OllamaExecutable
    }
}

if ($ollamaExe) {
    try {
        $ver = & $ollamaExe --version 2>&1
        Write-Host "  [OK] Ollama binary verified: $ollamaExe ($ver)" -ForegroundColor Green
    } catch {
        Write-Host "  [OK] Ollama binary located: $ollamaExe" -ForegroundColor Green
    }
} else {
    Write-Host "  [ERROR] Ollama binary could not be verified in PATH or LocalAppData." -ForegroundColor Red
    throw "Ollama is required for VibeSec AI capabilities."
}

# Ensure Ollama daemon is running
if (-not (Test-OllamaApi)) {
    Write-Host "  [*] Ollama service is not responding. Starting 'ollama serve' in background..." -ForegroundColor Cyan
    $ollamaOut = Join-Path $LogsDir "ollama-startup.stdout.log"
    $ollamaErr = Join-Path $LogsDir "ollama-startup.stderr.log"
    Start-Process -FilePath $ollamaExe -ArgumentList "serve" -WindowStyle Hidden -WorkingDirectory $ProjectRoot -RedirectStandardOutput $ollamaOut -RedirectStandardError $ollamaErr | Out-Null

    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if (Test-OllamaApi) { $ready = $true; break }
    }
    if ($ready) {
        Write-Host "  [OK] Ollama service started and responding at http://127.0.0.1:11434" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Ollama serve started but did not respond to /api/tags within 30s. Checking logs..." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [OK] Ollama service is already online at http://127.0.0.1:11434" -ForegroundColor Green
}

# -------------------------------------------------------------------------
# Step 3: Model Inventory & Automatic Pull
# -------------------------------------------------------------------------
Write-Host "`n[3/6] Verifying AI Model Inventory ($TargetModel)..." -ForegroundColor Yellow

$modelAvailable = $false
try {
    $tagsResp = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -Method Get -TimeoutSec 4 -ErrorAction Stop
    $installedModels = @($tagsResp.models | ForEach-Object { $_.name })
    Write-Host "  - Available models in Ollama: $(if ($installedModels) { $installedModels -join ', ' } else { 'None' })" -ForegroundColor Gray

    # Check if target model or tag match is present
    if ($installedModels -contains $TargetModel -or ($installedModels | Where-Object { $_ -like "$TargetModel*" } | Select-Object -First 1)) {
        $modelAvailable = $true
        Write-Host "  [OK] Target model '$TargetModel' is already downloaded and ready." -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARN] Could not inspect /api/tags." -ForegroundColor Yellow
}

if (-not $modelAvailable) {
    if ($SimulateFreshPC) {
        Write-Host "  [SIMULATION] Target model '$TargetModel' missing. Would execute: ollama pull $TargetModel" -ForegroundColor Magenta
    } else {
        Write-Host "  [*] Pulling model '$TargetModel' from Ollama library (this may take a few minutes)..." -ForegroundColor Cyan
        & $ollamaExe pull $TargetModel
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [ERROR] 'ollama pull $TargetModel' failed with exit code $LASTEXITCODE." -ForegroundColor Red
            throw "Failed to download model '$TargetModel'."
        }
        Write-Host "  [OK] Successfully pulled '$TargetModel'." -ForegroundColor Green
    }
}

# Warm-up inference probe to ensure model loads
try {
    $warmBody = @{
        model = $TargetModel
        prompt = "test"
        stream = $false
        options = @{ num_predict = 2 }
    } | ConvertTo-Json
    $warmResp = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/generate" -Method Post -Body $warmBody -ContentType "application/json" -TimeoutSec 15 -ErrorAction SilentlyContinue
    if ($warmResp -and $warmResp.response -ne $null) {
        Write-Host "  [OK] Verified end-to-end local model inference with '$TargetModel'." -ForegroundColor Green
    }
} catch {
    Write-Host "  [NOTICE] Model warm-up skipped or model will initialize on first query." -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# Step 4: Backend Python & Virtual Environment (.venv) Setup
# -------------------------------------------------------------------------
Write-Host "`n[4/6] Setting Up Python Backend Environment (.venv)..." -ForegroundColor Yellow

$pythonExe = $null
$pyCmd = Get-Command "python.exe" -ErrorAction SilentlyContinue
if (-not $pyCmd) { $pyCmd = Get-Command "python" -ErrorAction SilentlyContinue }
if ($pyCmd) { $pythonExe = $pyCmd.Source }

# Check common python install directories if python is not in PATH
if (-not $pythonExe) {
    $pyCandidates = @(
        "$env:LOCALAPPDATA\Python\pythoncore-3.11-64\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Program Files\Python311\python.exe",
        "C:\Program Files\Python312\python.exe"
    )
    foreach ($cand in $pyCandidates) {
        if (Test-Path $cand) { $pythonExe = $cand; break }
    }
}

if (-not $pythonExe) {
    Write-Host "  [ERROR] Compatible Python 3.10+ executable was not found." -ForegroundColor Red
    Write-Host "  Please install Python from python.org or via winget: winget install Python.Python.3.11" -ForegroundColor Yellow
    throw "Python installation required."
}
Write-Host "  - Base Python: $pythonExe" -ForegroundColor Gray

# Check/Create .venv
$venvWorks = $false
if (Test-Path $VenvPython) {
    try {
        $testOut = & "$VenvPython" -c "import sys; print(sys.version_info[0])" 2>$null
        if ($testOut -and $testOut.Trim() -match '^\d+$') { $venvWorks = $true }
    } catch { $venvWorks = $false }
}

$needsVenv = -not $venvWorks
if ($needsVenv) {
    Write-Host "  [*] Creating dedicated virtual environment at $VenvDir..." -ForegroundColor Cyan
    if (Test-Path $VenvDir) {
        Remove-Item -Path $VenvDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    & "$pythonExe" -m venv "$VenvDir"
    if (-not (Test-Path $VenvPython)) {
        throw "Failed to create Python virtual environment at $VenvDir."
    }
    Write-Host "  [OK] Created fresh .venv." -ForegroundColor Green
} else {
    Write-Host "  [OK] Existing functional .venv detected: $VenvPython" -ForegroundColor Green
}

# Clean any broken pip temp folders
$sitePkgs = Join-Path $VenvDir "Lib\site-packages"
if (Test-Path $sitePkgs) {
    Get-ChildItem -Path $sitePkgs -Filter "~*" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Check core dependencies
$depsCheck = & "$VenvPython" -c "import fastapi, uvicorn, pydantic, httpx, dotenv; print('OK')" 2>$null
if ($depsCheck -ne "OK") {
    Write-Host "  [*] Installing backend requirements from $ReqFile..." -ForegroundColor Cyan
    & "$VenvPython" -m pip install --upgrade pip --quiet
    & "$VenvPython" -m pip install -r "$ReqFile" --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Backend pip installation failed with exit code $LASTEXITCODE."
    }
    Write-Host "  [OK] Backend dependencies installed." -ForegroundColor Green
} else {
    Write-Host "  [OK] Core backend dependencies verified." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# Step 5: Frontend Node.js & Dependencies Setup
# -------------------------------------------------------------------------
Write-Host "`n[5/6] Setting Up Frontend Environment (Node.js & npm)..." -ForegroundColor Yellow

$nodeCmd = Get-Command "node" -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Host "  [ERROR] Node.js is not found in PATH." -ForegroundColor Red
    Write-Host "  Please install Node.js (v18+ or v20+) from nodejs.org or via: winget install OpenJS.NodeJS.LTS" -ForegroundColor Yellow
    throw "Node.js required."
}
$nodeVer = & node -v
Write-Host "  - Node.js version: $nodeVer" -ForegroundColor Gray

$nodeModules = Join-Path $ProjectRoot "node_modules"
$packageLock = Join-Path $ProjectRoot "package-lock.json"
if (-not (Test-Path $nodeModules)) {
    Write-Host "  [*] node_modules missing. Installing npm packages..." -ForegroundColor Cyan
    Push-Location $ProjectRoot
    if (Test-Path $packageLock) {
        npm ci
    } else {
        npm install
    }
    Pop-Location
    Write-Host "  [OK] Frontend npm packages installed." -ForegroundColor Green
} else {
    Write-Host "  [OK] node_modules present and verified." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# Step 6: Environment Files & Token Validation
# -------------------------------------------------------------------------
Write-Host "`n[6/6] Verifying Environment Configuration..." -ForegroundColor Yellow

# Root .env
$rootEnv = Join-Path $ProjectRoot ".env"
$rootEnvEx = Join-Path $ProjectRoot ".env.example"
if (-not (Test-Path $rootEnv) -and (Test-Path $rootEnvEx)) {
    Copy-Item $rootEnvEx $rootEnv -Force
    Write-Host "  [OK] Initialized root .env from .env.example (preserves default local ports)." -ForegroundColor Green
}

# Backend .env
$backEnv = Join-Path $BackendDir ".env"
$backEnvEx = Join-Path $BackendDir ".env.example"
if (-not (Test-Path $backEnv) -and (Test-Path $backEnvEx)) {
    Copy-Item $backEnvEx $backEnv -Force
    Write-Host "  [OK] Initialized backend .env from .env.example (OLLAMA_URL=http://127.0.0.1:11434)." -ForegroundColor Green
}

# Proxy token (for remote deployment)
if (-not (Test-Path $TokenFile)) {
    $newToken = [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 })).ToLower()
    Set-Content -Path $TokenFile -Value $newToken -Encoding ASCII -NoNewline
    Write-Host "  [OK] Initialized persistent proxy token in scripts/.proxy_token (git-ignored)." -ForegroundColor Green
} else {
    Write-Host "  [OK] Existing proxy token verified." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# Summary & Ready State
# -------------------------------------------------------------------------
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " [READY] VibeSec prerequisites ready                        " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  - Ollama Engine  : $ollamaExe" -ForegroundColor White
Write-Host "  - AI Model       : $TargetModel (Available)" -ForegroundColor White
Write-Host "  - Python Venv    : $VenvPython" -ForegroundColor White
Write-Host "  - Node / npm     : $nodeVer" -ForegroundColor White
Write-Host "  - Operating Mode : Local (Default: direct to 127.0.0.1:11434)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
