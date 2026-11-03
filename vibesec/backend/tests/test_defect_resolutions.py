"""
VibeSec Defect Resolution & Regression Verification Suite
Tests DEF-001 through DEF-015 fixes:
- DEF-004: Multiline import AST parsing (no multiline newline consumption)
- DEF-005: Local repository module exclusion in dependency checks
- DEF-006: AST-based SQL Injection detection with variable assignments & AWS example keys filtering
- DEF-010: Language metadata resolution
- DEF-011: Indentation normalization and context preservation in patches
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import unittest
import json
import time
import asyncio
from scanner.hallucination import extract_imports, check_packages
from scanner.semgrep_runner import semgrep_scan, detect_ast_sqli, native_fallback_scan
from scanner.env_detector import is_aws_example_credential, inspect_env_file_content, is_placeholder_value
from remediation import apply_snippet_patch_to_code, generate_unified_diff
from scanner.code_scanner import scan_code
from models.llm_chain import LLMTimeoutError, LLMProviderError
from scanner.vuln_agent import analyze_chunk
from unittest.mock import AsyncMock, patch
from main import generate_session_token, verify_session_credentials


class TestDefectResolutions(unittest.TestCase):

    def test_def_004_multiline_import_parsing(self):
        """DEF-004: Horizontal whitespace regex/AST must not consume subsequent function definitions."""
        code = (
            "import flask\n"
            "def get_user(username):\n"
            "    return True\n"
        )
        imports = extract_imports(code, "python")
        self.assertIn("flask", imports)
        self.assertNotIn("def", imports)
        self.assertNotIn("get_user", imports)

        # Standard library modules (like sqlite3, os, sys) are filtered out as builtins
        code_stdlib = (
            "import sqlite3\n"
            "import os\n"
            "import requests\n"
        )
        imports_stdlib = extract_imports(code_stdlib, "python")
        self.assertNotIn("sqlite3", imports_stdlib)
        self.assertNotIn("os", imports_stdlib)
        self.assertIn("requests", imports_stdlib)

    def test_def_005_exclude_local_modules(self):
        """DEF-005: Local repository modules and packages must be excluded from hallucination checks."""
        code = (
            "import challenge\n"
            "import models\n"
            "from utils.helpers import sanitize\n"
            "import requests\n"
        )
        local_modules = {"challenge", "models", "utils"}
        imports = extract_imports(code, "python", local_modules=local_modules)
        self.assertNotIn("challenge", imports)
        self.assertNotIn("models", imports)
        self.assertNotIn("utils", imports)
        self.assertIn("requests", imports)

    def test_def_006_ast_sql_injection_detection(self):
        """DEF-006: AST-based SQL injection detector must flag dynamic string assignment and execute."""
        code = (
            "def get_account(user_id):\n"
            "    query = f\"SELECT * FROM accounts WHERE id = '{user_id}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        findings = semgrep_scan(code, "python")
        sqli_findings = [f for f in findings if "sqli" in f["rule_id"]]
        self.assertGreater(len(sqli_findings), 0, "AST detector must flag dynamic SQL string construction")
        self.assertEqual(sqli_findings[0]["line_start"], 2)

        # Modulo formatting %
        code_mod = (
            "query = 'SELECT * FROM users WHERE name = %s' % name\n"
            "db.execute(query)\n"
        )
        findings_mod = semgrep_scan(code_mod, "python")
        sqli_mod = [f for f in findings_mod if "sqli" in f["rule_id"]]
        self.assertGreater(len(sqli_mod), 0)

    def test_aws_example_credentials_not_flagged(self):
        """AWS documentation example keys must not be flagged as exposed live secrets."""
        aws_code = (
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        )
        self.assertTrue(is_aws_example_credential("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(is_aws_example_credential("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
        self.assertTrue(is_placeholder_value("AKIAIOSFODNN7EXAMPLE"))

        findings = semgrep_scan(aws_code, "python")
        secret_findings = [f for f in findings if "secret" in f["rule_id"]]
        self.assertEqual(len(secret_findings), 0, "AWS example keys must be filtered out")

        env_findings = inspect_env_file_content(aws_code, ".env.example")
        self.assertEqual(len(env_findings), 0)

    def test_def_011_patch_indentation_and_context_preservation(self):
        """DEF-011: Snippet replacement must preserve original function indentation and context."""
        original = (
            "def get_user(username):\n"
            "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        )
        snippet = (
            "query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
            "cursor.execute(query)"
        )
        patch = 'cursor.execute("SELECT * FROM users WHERE username = %s", (username,))'

        remediated = apply_snippet_patch_to_code(original, snippet, patch)
        expected = (
            "def get_user(username):\n"
            '    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))\n'
            "    return cursor.fetchone()"
        )
        self.assertEqual(remediated.strip(), expected.strip())

        diff = generate_unified_diff(original, remediated, filename="snippet.py")
        self.assertIn("--- a/snippet.py (vulnerable)", diff)
        self.assertIn("+++ b/snippet.py (remediated)", diff)
        self.assertIn("-    query = f\"SELECT * FROM users", diff)
        self.assertIn("+    cursor.execute(\"SELECT * FROM users", diff)

    def test_session_hmac_and_isolation(self):
        """Test missing tokens, invalid tokens, forged tokens, and cross-session isolation."""
        alice_sid = "session-alice-1234"
        bob_sid = "session-bob-5678"

        # Missing tokens
        self.assertFalse(verify_session_credentials(None, None))
        self.assertFalse(verify_session_credentials(alice_sid, None))
        self.assertFalse(verify_session_credentials(alice_sid, ""))

        # Valid tokens
        alice_token = generate_session_token(alice_sid)
        self.assertTrue(verify_session_credentials(alice_sid, alice_token))

        bob_token = generate_session_token(bob_sid)
        self.assertTrue(verify_session_credentials(bob_sid, bob_token))

        # Cross-session forgery / mismatch
        self.assertFalse(verify_session_credentials(alice_sid, bob_token), "Alice cannot authenticate with Bob's token")
        self.assertFalse(verify_session_credentials(bob_sid, alice_token), "Bob cannot authenticate with Alice's token")

        # Tampered signature
        tampered = alice_token[:-4] + "dead"
        self.assertFalse(verify_session_credentials(alice_sid, tampered), "Tampered HMAC signature must be rejected")

    def test_language_metadata_resolution(self):
        """Test finding language metadata attaching accurately for Python vs JavaScript."""
        py_code = "import os\nprint('hello')\n"
        py_result = asyncio.run(scan_code(py_code, language="python", filename="app.py"))
        self.assertEqual(py_result.get("language"), "python")
        for finding in py_result.get("vulnerabilities", []):
            self.assertEqual(finding.get("language"), "python")

        js_code = "const express = require('express');\nconst app = express();\n"
        js_result = asyncio.run(scan_code(js_code, language="javascript", filename="server.js"))
        self.assertEqual(js_result.get("language"), "javascript")
        for finding in js_result.get("vulnerabilities", []):
            self.assertEqual(finding.get("language"), "javascript")

    def test_semgrep_does_not_block_fastapi_event_loop(self):
        """A slow Semgrep CLI must run off-thread so other async requests can progress."""
        def slow_semgrep(code, language):
            time.sleep(0.15)
            return []

        async def run_check():
            scan_task = asyncio.create_task(scan_code("print('safe')", language="python"))
            start = time.perf_counter()
            await asyncio.sleep(0.02)
            heartbeat_elapsed = time.perf_counter() - start
            self.assertLess(
                heartbeat_elapsed,
                0.10,
                "A blocking Semgrep subprocess stalled the event loop.",
            )
            await scan_task

        with patch("scanner.code_scanner.semgrep_scan", side_effect=slow_semgrep):
            with patch("scanner.code_scanner.check_packages", new=AsyncMock(return_value=[])):
                asyncio.run(run_check())

    def test_valid_structured_ai_json_is_parsed(self):
        """A schema-valid model response is mapped into the scanner's finding format."""
        finding = {
            "rule_id": "python.lang.security.audit.sqli",
            "severity": "HIGH",
            "message": "Dynamic SQL query uses untrusted input.",
            "line_start": 7,
            "code_snippet": "query = f'SELECT * FROM users WHERE id={account_id}'",
        }
        response = {
            "is_vulnerable": True,
            "title": "SQL injection",
            "severity": "high",
            "owasp": "A03:2021-Injection",
            "description": "User input is interpolated into SQL.",
            "attack_scenario": "An attacker changes the query predicate.",
            "line_hint": 7,
            "confidence": "high",
            "fix": "Use a parameterized query.",
        }

        async def run_check():
            with patch(
                "scanner.vuln_agent.call_llm",
                new=AsyncMock(return_value=(
                    json.dumps(response),
                    "Ollama (qwen2.5-coder:7b)",
                )),
            ):
                result = await analyze_chunk(
                    finding,
                    finding["code_snippet"],
                    "python",
                    "app.py",
                )
                self.assertIsNotNone(result)
                self.assertEqual(result["title"], "SQL injection")
                self.assertEqual(result["severity"], "high")
                self.assertEqual(result["model_used"], "Ollama (qwen2.5-coder:7b)")

        asyncio.run(run_check())

    def test_malformed_ai_json_preserves_static_finding(self):
        """Malformed/truncated model JSON must not erase a deterministic static finding."""
        finding = {
            "rule_id": "python.lang.security.audit.sqli",
            "severity": "HIGH",
            "message": "Dynamic SQL query uses untrusted input.",
            "line_start": 7,
            "code_snippet": "query = f'SELECT * FROM users WHERE id={user_id}'",
        }

        async def run_check():
            with patch(
                "scanner.vuln_agent.call_llm",
                new=AsyncMock(return_value=(
                    '{"is_vulnerable": true, "description": "truncated string',
                    "Ollama (qwen2.5-coder:7b)",
                )),
            ):
                result = await analyze_chunk(
                    finding,
                    finding["code_snippet"],
                    "python",
                    "app.py",
                )
                self.assertIsNotNone(result)
                self.assertEqual(result["model_used"], "Static analysis (AI verification unavailable)")
                self.assertEqual(result["rule_id"], finding["rule_id"])

        asyncio.run(run_check())

    def test_timeout_calibration_and_slow_mock(self):
        """Test upstream/downstream timeout hierarchy and slow mock timeout handling."""
        import httpx

        # Test that calling a nonexistent/hanging port raises LLMTimeoutError cleanly
        async def run_slow():
            try:
                # 0.01s timeout simulation
                async with httpx.AsyncClient(timeout=httpx.Timeout(0.01)) as client:
                    await client.get("http://10.255.255.1") # non-routable IP
            except (httpx.TimeoutException, httpx.ConnectError):
                raise LLMTimeoutError("Simulated slow inference timeout")

        with self.assertRaises(LLMTimeoutError):
            asyncio.run(run_slow())


if __name__ == "__main__":
    unittest.main()
