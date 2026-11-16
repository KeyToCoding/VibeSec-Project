import json
import re

# 1. Update .vscode/tasks.json
with open('.vscode/tasks.json', 'r', encoding='utf-8') as f:
    tasks_text = f.read()

# Remove group from Antigravity Integrated
antigravity_group_pat = re.compile(
    r'("label":\s*"VibeSec:\s*Start All \(Antigravity Integrated\)",\s*"dependsOn":\s*\[[^\]]*\],\s*"dependsOrder":\s*"sequence",)\s*"group":\s*\{\s*"kind":\s*"build",\s*"isDefault":\s*true\s*\},',
    re.DOTALL
)

if antigravity_group_pat.search(tasks_text):
    tasks_text = antigravity_group_pat.sub(r'\1', tasks_text, count=1)
    print("Removed default build group from Antigravity Integrated")
else:
    print("Warning: Antigravity Integrated group pattern not found directly, will check JSON parse")

# Add group to Local Mode
local_mode_pat = re.compile(
    r'("label":\s*"VibeSec:\s*Start All \(Local Mode\)",\s*"dependsOn":\s*\[[^\]]*\],\s*"dependsOrder":\s*"sequence",)',
    re.DOTALL
)

if local_mode_pat.search(tasks_text):
    tasks_text = local_mode_pat.sub(
        r'\1\n      "group": {\n        "kind": "build",\n        "isDefault": true\n      },',
        tasks_text,
        count=1
    )
    print("Added default build group to Local Mode")
else:
    print("Warning: Local Mode pattern not found directly")

# Validate that tasks_text is valid JSON
try:
    data = json.loads(tasks_text)
    print("JSON validation passed for .vscode/tasks.json")
    # Verify exact group settings
    for t in data.get("tasks", []):
        if t.get("label") == "VibeSec: Start All (Local Mode)":
            assert t.get("group", {}).get("isDefault") is True, "Local Mode isDefault must be True"
        if t.get("label") == "VibeSec: Start All (Antigravity Integrated)":
            assert t.get("group") is None, "Antigravity Integrated group must be None"
    print("Verification: VibeSec Start All (Local Mode) is now the ONLY default build task!")
except Exception as e:
    raise RuntimeError(f"Failed to parse or validate tasks.json: {e}")

with open('.vscode/tasks.json', 'w', encoding='utf-8') as f:
    f.write(tasks_text)

# 2. Update scripts/Setup-VibeSec-Prerequisites.ps1 Python priority
with open('scripts/Setup-VibeSec-Prerequisites.ps1', 'r', encoding='utf-8') as f:
    setup_text = f.read()

has_crlf = '\r\n' in setup_text
setup_norm = setup_text.replace('\r\n', '\n')

old_py_block = '''$pythonExe = $null
$pyCmd = Get-Command "python.exe" -ErrorAction SilentlyContinue
if (-not $pyCmd) { $pyCmd = Get-Command "python" -ErrorAction SilentlyContinue }
if ($pyCmd) { $pythonExe = $pyCmd.Source }

# Check common python install directories if python is not in PATH
if (-not $pythonExe) {
    $pyCandidates = @(
        "$env:LOCALAPPDATA\\Python\\pythoncore-3.11-64\\python.exe",
        "$env:LOCALAPPDATA\\Programs\\Python\\Python311\\python.exe",
        "$env:LOCALAPPDATA\\Programs\\Python\\Python312\\python.exe",
        "$env:LOCALAPPDATA\\Programs\\Python\\Python310\\python.exe",
        "C:\\Program Files\\Python311\\python.exe",
        "C:\\Program Files\\Python312\\python.exe"
    )
    foreach ($cand in $pyCandidates) {
        if (Test-Path $cand) { $pythonExe = $cand; break }
    }
}'''

new_py_block = '''$pythonExe = $null

# Prioritize Python 3.11 / 3.12 installs (avoids Python 3.14 alpha/pre-release build issues)
$pyCandidates = @(
    "$env:LOCALAPPDATA\\Python\\pythoncore-3.11-64\\python.exe",
    "$env:LOCALAPPDATA\\Programs\\Python\\Python311\\python.exe",
    "C:\\Program Files\\Python311\\python.exe",
    "$env:LOCALAPPDATA\\Programs\\Python\\Python312\\python.exe",
    "C:\\Program Files\\Python312\\python.exe"
)
foreach ($cand in $pyCandidates) {
    if (Test-Path $cand) { $pythonExe = $cand; break }
}

if (-not $pythonExe) {
    $pyCmd = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if (-not $pyCmd) { $pyCmd = Get-Command "python" -ErrorAction SilentlyContinue }
    if ($pyCmd) { $pythonExe = $pyCmd.Source }
}'''

if old_py_block in setup_norm:
    setup_norm = setup_norm.replace(old_py_block, new_py_block, 1)
    print("Updated Python 3.11 priority in Setup-VibeSec-Prerequisites.ps1")
else:
    print("Warning: old_py_block not found in Setup-VibeSec-Prerequisites.ps1")

lines = [l.rstrip() for l in setup_norm.split('\n')]
setup_norm = '\n'.join(lines) + '\n'
if has_crlf:
    setup_norm = setup_norm.replace('\n', '\r\n')

with open('scripts/Setup-VibeSec-Prerequisites.ps1', 'w', encoding='utf-8') as f:
    f.write(setup_norm)

# 3. Update scripts/Start-VibeSec.ps1 browser launch
with open('scripts/Start-VibeSec.ps1', 'r', encoding='utf-8') as f:
    start_text = f.read()

has_crlf_s = '\r\n' in start_text
start_norm = start_text.replace('\r\n', '\n')

old_start_end = '''Write-Host "====================================================" -ForegroundColor Cyan'''

new_start_end = '''Write-Host "====================================================" -ForegroundColor Cyan

if (-not $NoBrowser) {
    Write-Host "`n[*] Opening http://localhost:3000 in your browser..." -ForegroundColor Cyan
    Start-Process "http://localhost:3000" | Out-Null
}'''

# Replace only the final occurrence
if 'if (-not $NoBrowser)' not in start_norm:
    r_idx = start_norm.rfind(old_start_end)
    if r_idx != -1:
        start_norm = start_norm[:r_idx] + new_start_end + start_norm[r_idx + len(old_start_end):]
        print("Added browser launch to Start-VibeSec.ps1")

lines_s = [l.rstrip() for l in start_norm.split('\n')]
start_norm = '\n'.join(lines_s) + '\n'
if has_crlf_s:
    start_norm = start_norm.replace('\n', '\r\n')

with open('scripts/Start-VibeSec.ps1', 'w', encoding='utf-8') as f:
    f.write(start_norm)

print("All configuration updates completed successfully.")

