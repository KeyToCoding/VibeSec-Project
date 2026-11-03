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
import ast
from typing import List, Dict, Any, Optional

try:
    from .env_detector import is_aws_example_credential
except ImportError:
    from env_detector import is_aws_example_credential

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
        "regex": r"(SELECT\s+.*FROM\s+.*WHERE\s+.*['\"]\s*\+|cursor\.execute\s*\(\s*f[\"']|\.execute\s*\(\s*[\"'].*\%|\.query\s*\(\s*[`'\"].*\$\{)|(f[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^\"']*\{)|(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\%[sdb])|(\b(SELECT|INSERT|UPDATE|DELETE)\s+.*['\"]\s*\+\s*[a-zA-Z0-9_]+)",
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


SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "alter", "where", "from", "table", "union"}


def _is_sql_text(text: str) -> bool:
    tokens = set(re.findall(r"\b[a-zA-Z]+\b", text.lower()))
    return bool(tokens & SQL_KEYWORDS)


def _is_dynamic_sql_expr(node: ast.AST) -> bool:
    """Check if AST node builds a dynamic SQL string."""
    if isinstance(node, ast.JoinedStr):
        has_sql = False
        has_expr = False
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if _is_sql_text(part.value):
                    has_sql = True
            elif isinstance(part, ast.FormattedValue):
                has_expr = True
        return has_sql and has_expr
    elif isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                if _is_sql_text(node.left.value):
                    return True
        elif isinstance(node.op, ast.Add):
            left_sql = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and _is_sql_text(node.left.value)
            right_sql = isinstance(node.right, ast.Constant) and isinstance(node.right.value, str) and _is_sql_text(node.right.value)
            if left_sql or right_sql or _is_dynamic_sql_expr(node.left) or _is_dynamic_sql_expr(node.right):
                return True
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                if _is_sql_text(node.func.value.value):
                    return True
    return False


def detect_ast_sqli(code: str, lines: List[str]) -> List[Dict[str, Any]]:
    """AST-based SQL injection detector for Python."""
    findings = []
    try:
        tree = ast.parse(code)
    except Exception:
        return findings

    dynamic_sql_vars: Dict[str, int] = {}

    class SQLiVisitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign):
            if _is_dynamic_sql_expr(node.value):
                line_no = getattr(node, "lineno", 1)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        dynamic_sql_vars[target.id] = line_no
                findings.append({
                    "rule_id": "vibesec.sqli.raw-string-concat",
                    "severity": "HIGH",
                    "message": "Potential SQL Injection: Dynamic SQL string constructed via string interpolation/formatting.",
                    "line_start": line_no,
                    "line_end": getattr(node, "end_lineno", line_no),
                    "code_snippet": extract_context(lines, line_no, getattr(node, "end_lineno", line_no), context_size=3)
                })
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):
            line_no = getattr(node, "lineno", 1)
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr.lower()
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id.lower()

            sql_exec_methods = {"execute", "executemany", "raw", "query", "execute_query"}
            if func_name in sql_exec_methods and node.args:
                first_arg = node.args[0]
                if _is_dynamic_sql_expr(first_arg):
                    findings.append({
                        "rule_id": "vibesec.sqli.raw-string-concat",
                        "severity": "HIGH",
                        "message": "Potential SQL Injection: Unparameterized dynamic query passed directly to SQL execution function.",
                        "line_start": line_no,
                        "line_end": getattr(node, "end_lineno", line_no),
                        "code_snippet": extract_context(lines, line_no, getattr(node, "end_lineno", line_no), context_size=3)
                    })
                elif isinstance(first_arg, ast.Name) and first_arg.id in dynamic_sql_vars:
                    pass
            self.generic_visit(node)

    SQLiVisitor().visit(tree)
    seen_lines = set()
    deduped = []
    for f in findings:
        if f["line_start"] not in seen_lines:
            seen_lines.add(f["line_start"])
            deduped.append(f)
    return deduped


def native_fallback_scan(code: str, language: str) -> List[Dict[str, Any]]:
    """Native static pattern matcher when Semgrep is unavailable."""
    findings = []
    lines = code.splitlines()

    # If Python, run AST-based SQL injection detector
    if language.lower() in ("python", "py"):
        ast_findings = detect_ast_sqli(code, lines)
        findings.extend(ast_findings)

    existing_sqli_lines = {f["line_start"] for f in findings if "sqli" in f["rule_id"]}

    for pattern in BUILTIN_PATTERNS:
        compiled = re.compile(pattern["regex"], re.IGNORECASE)
        for i, line in enumerate(lines, start=1):
            match = compiled.search(line)
            if match:
                if pattern["id"] == "vibesec.sqli.raw-string-concat" and i in existing_sqli_lines:
                    continue
                if pattern["id"] == "vibesec.secrets.hardcoded-key":
                    matched_text = match.group(0)
                    if is_aws_example_credential(matched_text):
                        continue
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
    elif language.lower() in ("python", "py"):
        ast_findings = detect_ast_sqli(code, code_lines)
        existing_lines = {f["line_start"] for f in findings if "sql" in f["rule_id"].lower()}
        for af in ast_findings:
            if af["line_start"] not in existing_lines:
                findings.append(af)

    return findings
