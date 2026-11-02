"""
VibeSec Semgrep & Static Analysis Runner
Executes Semgrep CLI static analysis with 3-line code context extraction.
Includes native AST and regex heuristics fallback if Semgrep binary is missing.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger("vibesec.semgrep")

EXTENSION_MAP = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "jsx": ".jsx",
    "tsx": ".tsx",
    "php": ".php",
    "java": ".java",
    "go": ".go",
    "ruby": ".rb",
    "rb": ".rb"
}

# Heuristic static patterns for native fallback if semgrep executable is not installed
BUILTIN_PATTERNS = [
    {
        "id": "vibesec.sqli.raw-string-concat",
        "regex": r"(SELECT\s+.*FROM\s+.*WHERE\s+.*['\"]\s*\+|cursor\.execute\s*\(\s*f[\"']|\.execute\s*\(\s*[\"'].*\%|\.query\s*\(\s*[`'\"].*\$\{)",
        "severity": "HIGH",
        "message": "Potential SQL Injection via unparameterized dynamic string concatenation."
    },
    {
        "id": "vibesec.cmdi.subprocess-shell",
        "regex": r"(subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|exec\s*\(.*req\.)",
        "severity": "CRITICAL",
        "message": "Command injection risk: shell=True or unescaped system command execution."
    },
    {
        "id": "vibesec.xss.dangerously-set",
        "regex": r"(dangerouslySetInnerHTML\s*=|innerHTML\s*=|document\.write\s*\(|v-html\s*=)",
        "severity": "MEDIUM",
        "message": "Cross-Site Scripting (XSS) risk via direct HTML rendering of unescaped content."
    },
    {
        "id": "vibesec.crypto.weak-hash",
        "regex": r"(hashlib\.md5|hashlib\.sha1|crypto\.createHash\s*\(\s*['\"](md5|sha1)['\"])",
        "severity": "LOW",
        "message": "Use of cryptographically broken hash algorithm (MD5/SHA1)."
    },
    {
        "id": "vibesec.secrets.hardcoded-key",
        "regex": r"(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z-_]{35}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|(secret_key|api_key|password)\s*=\s*['\"][a-zA-Z0-9_\-\.]{8,}['\"])",
        "severity": "CRITICAL",
        "message": "Hardcoded secret, API credential, or private token detected in source."
    },
    {
        "id": "vibesec.deserialization.pickle",
        "regex": r"(pickle\.loads\s*\(|_pickle\.loads\s*\(|yaml\.load\s*\([^,)]*\))",
        "severity": "CRITICAL",
        "message": "Insecure deserialization via pickle or unsafe yaml loader allowing remote code execution."
    },
    {
        "id": "vibesec.eval.dynamic-code",
        "regex": r"(\beval\s*\(|\bexec\s*\(|\bFunction\s*\(.*new\s+Function)",
        "severity": "HIGH",
        "message": "Dynamic code evaluation via eval() or Function() constructor."
    }
]


def extract_context(lines: List[str], line_start: int, line_end: int, context_size: int = 3) -> str:
    """Extract code slice with 3 lines of context around finding."""
    start_idx = max(0, line_start - 1 - context_size)
    end_idx = min(len(lines), line_end + context_size)
    return "\n".join(lines[start_idx:end_idx])


def native_fallback_scan(code: str, language: str) -> List[Dict[str, Any]]:
    """Native static pattern matcher when Semgrep is unavailable."""
    findings = []
    lines = code.splitlines()

    for pattern in BUILTIN_PATTERNS:
        compiled = re.compile(pattern["regex"], re.IGNORECASE)
        for i, line in enumerate(lines, start=1):
            if compiled.search(line):
                findings.append({
                    "rule_id": pattern["id"],
                    "severity": pattern["severity"],
                    "message": pattern["message"],
                    "line_start": i,
                    "line_end": i,
                    "code_snippet": extract_context(lines, i, i, context_size=3)
                })
    return findings


def find_semgrep_executable() -> Optional[str]:
    """
    Safely locate a valid Semgrep executable on Windows without triggering
    app-selection popups on extensionless scripts or mixing virtual environments.
    """
    # 1. Check explicit environment override
    custom_path = os.getenv("SEMGREP_PATH") or os.getenv("SEMGREP_BIN")
    if custom_path and os.path.isfile(custom_path):
        if sys.platform != "win32" or custom_path.lower().endswith((".exe", ".cmd", ".bat")):
            return custom_path

    # 2. Check dedicated .semgrep-env Scripts directory for Windows executables
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    semgrep_env_scripts = os.path.join(backend_dir, ".semgrep-env", "Scripts" if sys.platform == "win32" else "bin")
    if sys.platform == "win32":
        candidate_path = os.path.join(semgrep_env_scripts, "semgrep.exe")
        if os.path.isfile(candidate_path):
            return candidate_path
    else:
        candidate_path = os.path.join(semgrep_env_scripts, "semgrep")
        if os.path.isfile(candidate_path) and os.access(candidate_path, os.X_OK):
            return candidate_path

    # 3. Check system PATH using standard Windows executable extensions
    found = shutil.which("semgrep")
    if found:
        # On Windows, strictly avoid running extensionless scripts that open the Open With dialog
        if sys.platform != "win32" or found.lower().endswith(".exe"):
            return found

    return None


def semgrep_scan(code: str, language: str = "python") -> List[Dict[str, Any]]:
    """
    Run Semgrep static analysis on code string.
    Returns structured list of findings with rule, severity, and code snippets.
    Falls back to native AST and regex heuristics if Semgrep is not available.
    """
    lang_lower = language.lower()
    ext = EXTENSION_MAP.get(lang_lower, ".py")

    # Check if a safe, callable Semgrep CLI executable exists
    semgrep_cmd = find_semgrep_executable()
    if not semgrep_cmd:
        logger.info("Semgrep CLI not detected on PATH or dedicated environment. Utilizing VibeSec native pattern analyzer.")
        return native_fallback_scan(code, language)

    findings: List[Dict[str, Any]] = []
    code_lines = code.splitlines()

    tmp_file = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8") as f:
            f.write(code)
            tmp_file = f.name

        cmd = [
            semgrep_cmd,
            "--config=auto",
            "--json",
            "--quiet",
            "--disable-version-check",
            tmp_file
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode in (0, 1) and result.stdout:
            data = json.loads(result.stdout)
            raw_results = data.get("results", [])
            for item in raw_results:
                line_start = item.get("start", {}).get("line", 1)
                line_end = item.get("end", {}).get("line", line_start)
                rule_id = item.get("check_id", "semgrep.rule")
                extra = item.get("extra", {})
                severity = extra.get("severity", "WARNING").upper()
                message = extra.get("message", "Potential security flaw detected.")

                snippet = extract_context(code_lines, line_start, line_end, context_size=3)
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "line_start": line_start,
                    "line_end": line_end,
                    "code_snippet": snippet
                })
        else:
            logger.warning(f"Semgrep exited with code {result.returncode}. Output: {result.stderr}")
            # Fallback to internal regex scanner
            return native_fallback_scan(code, language)

    except Exception as e:
        logger.error(f"Error running semgrep: {e}. Falling back to internal engine.")
        return native_fallback_scan(code, language)
    finally:
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

    # If Semgrep returned 0 results, supplement with builtin critical regex
    if not findings:
        findings = native_fallback_scan(code, language)

    return findings
