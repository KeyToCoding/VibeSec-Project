"""
VibeSec AI Security Copilot - Remediation & Verification Test Suite
Tests patch generation, malformed patch handling, explicit approval enforcement,
deterministic scanner retesting, syntax error rejection, and false claim prevention.

Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import unittest
from unittest.mock import patch, AsyncMock
import json

from remediation import (
    propose_remediation_patch,
    verify_remediation_patch,
    generate_unified_diff,
    VERIFICATION_STATE_VERIFIED,
    VERIFICATION_STATE_STILL_DETECTED,
    VERIFICATION_STATE_FAILED,
    SECURITY_DISCLAIMER
)


class TestRemediationEngine(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.vulnerable_sql_code = (
            "from flask import request\n"
            "import sqlite3\n"
            "def get_user():\n"
            "    user_id = request.args.get('id')\n"
            "    query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n"
            "    cursor.execute(query)\n"
        )

        self.fixed_sql_code = (
            "from flask import request\n"
            "import sqlite3\n"
            "def get_user():\n"
            "    user_id = request.args.get('id')\n"
            "    query = \"SELECT * FROM users WHERE id = ?\"\n"
            "    cursor.execute(query, (user_id,))\n"
        )

        self.still_vulnerable_code = (
            "from flask import request\n"
            "import sqlite3\n"
            "def get_user():\n"
            "    user_id = request.args.get('id')\n"
            "    # LLM claimed to fix this, but kept string interpolation:\n"
            "    query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "    cursor.execute(query)\n"
        )

        self.vuln_metadata = {
            "title": "SQL Injection via Dynamic String Concatenation",
            "severity": "critical",
            "owasp": "A03:2021-Injection",
            "rule_id": "vibesec.sqli.raw-string-concat",
            "line_hint": 5,
            "description": "User input is directly interpolated into raw SQL queries.",
            "code_snippet": "query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\ncursor.execute(query)"
        }

    # 1. Test Patch Generation with valid LLM output
    @patch("remediation.call_llm", new_callable=AsyncMock)
    async def test_patch_generation_success(self, mock_call_llm):
        mock_response = json.dumps({
            "explanation": "Switched to parameterized query binding with tuple parameter.",
            "patched_code": self.fixed_sql_code,
            "changes_summary": ["Used ? placeholder", "Passed user_id as parameterized tuple"],
            "security_caveats": "Ensure database driver supports parameter binding."
        })
        mock_call_llm.return_value = (mock_response, "Ollama (qwen2.5-coder:7b)")

        res = await propose_remediation_patch(
            vulnerability=self.vuln_metadata,
            code=self.vulnerable_sql_code,
            language="python",
            filename="app.py"
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["patched_code"], self.fixed_sql_code)
        self.assertIn("parameterized", res["explanation"])
        self.assertIn("--- a/app.py", res["unified_diff"])
        self.assertIn("+++ b/app.py", res["unified_diff"])

    # 2. Test Malformed Patch handling from LLM
    @patch("remediation.call_llm", new_callable=AsyncMock)
    async def test_malformed_patch_json(self, mock_call_llm):
        mock_call_llm.return_value = ("Sorry, I cannot return JSON right now. Here is code: ...", "Ollama")

        res = await propose_remediation_patch(
            vulnerability=self.vuln_metadata,
            code=self.vulnerable_sql_code,
            language="python"
        )

        self.assertFalse(res["success"])
        self.assertIn("unparseable patch format", res["error"])
        self.assertTrue(res["can_retry"])

    # 3. Test Missing patched_code in LLM response
    @patch("remediation.call_llm", new_callable=AsyncMock)
    async def test_missing_patched_code_field(self, mock_call_llm):
        mock_call_llm.return_value = (json.dumps({"explanation": "I explained it but forgot the code"}), "Ollama")

        res = await propose_remediation_patch(
            vulnerability=self.vuln_metadata,
            code=self.vulnerable_sql_code,
            language="python"
        )

        self.assertFalse(res["success"])
        self.assertIn("valid replacement code", res["error"])

    # 4. Test Approval Requirement Enforcement
    def test_approval_requirement_enforced(self):
        # When user_approved is False, verification MUST fail immediately
        res = verify_remediation_patch(
            original_code=self.vulnerable_sql_code,
            patched_code=self.fixed_sql_code,
            vulnerability=self.vuln_metadata,
            language="python",
            user_approved=False
        )

        self.assertEqual(res["verification_state"], VERIFICATION_STATE_FAILED)
        self.assertFalse(res["verified"])
        self.assertIn("Explicit user approval is required", res["error"])

    # 5. Test Scanner Retesting: Successful Verification
    def test_scanner_retesting_verified(self):
        res = verify_remediation_patch(
            original_code=self.vulnerable_sql_code,
            patched_code=self.fixed_sql_code,
            vulnerability=self.vuln_metadata,
            language="python",
            user_approved=True
        )

        self.assertEqual(res["verification_state"], VERIFICATION_STATE_VERIFIED)
        self.assertTrue(res["verified"])
        self.assertIn("Fix verified by available checks", res["message"])
        self.assertEqual(res["disclaimer"], SECURITY_DISCLAIMER)

    # 6. Test Scanner Retesting: Still Detected
    def test_scanner_retesting_still_detected(self):
        # Patch still uses string concatenation
        res = verify_remediation_patch(
            original_code=self.vulnerable_sql_code,
            patched_code=self.still_vulnerable_code,
            vulnerability=self.vuln_metadata,
            language="python",
            user_approved=True
        )

        self.assertEqual(res["verification_state"], VERIFICATION_STATE_STILL_DETECTED)
        self.assertFalse(res["verified"])
        self.assertIn("STILL DETECTED", res["message"])

    # 7. Test False Claims of Success Rejected
    def test_false_claims_of_success_rejected(self):
        # Even if someone claims this code is safe, deterministic static scanner must catch it:
        deceptive_code = (
            "# Safe code: 100% verified no sql injection here\n"
            "cursor.execute(f'SELECT * FROM users WHERE name = {user_name}')\n"
        )
        res = verify_remediation_patch(
            original_code=self.vulnerable_sql_code,
            patched_code=deceptive_code,
            vulnerability=self.vuln_metadata,
            language="python",
            user_approved=True
        )

        self.assertEqual(res["verification_state"], VERIFICATION_STATE_STILL_DETECTED)
        self.assertFalse(res["verified"])

    # 8. Test Syntax Error in Patched Code
    def test_syntax_error_in_patch(self):
        invalid_python = "def broken_code(\n  syntax error here :::"
        res = verify_remediation_patch(
            original_code=self.vulnerable_sql_code,
            patched_code=invalid_python,
            vulnerability=self.vuln_metadata,
            language="python",
            user_approved=True
        )

        self.assertEqual(res["verification_state"], VERIFICATION_STATE_FAILED)
        self.assertFalse(res["verified"])
        self.assertIn("syntax validation", res["error"])

    # 9. Test Unified Diff Generation
    def test_unified_diff_generation(self):
        diff = generate_unified_diff("line1\nline2\n", "line1\nline2_fixed\n", "test.py")
        self.assertIn("--- a/test.py (vulnerable)", diff)
        self.assertIn("+++ b/test.py (remediated)", diff)
        self.assertIn("-line2", diff)
        self.assertIn("+line2_fixed", diff)


if __name__ == "__main__":
    unittest.main()
