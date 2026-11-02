"""Tests for VibeSec Environment File & Secret Detector.
Covers:
1. Safe templates (.env.example, .env.sample, .env.template) with placeholders -> 0 findings
2. Real credentials in templates -> reported as Exposed Credential in Environment Template
3. Committed runtime .env files (.env, .env.production) with genuine secrets -> reported
4. Committed runtime .env files with only safe placeholders -> 0 false positives
5. Detection of placeholder values (YOUR_API_KEY, CHANGE_ME, <your_key>, localhost, etc.)
6. File-level findings in remediation copilot -> returns actionable remediation instructions without requiring code
7. API /api/remediate/propose-patch accepts file-level finding with empty code snippet and returns 200
"""

import unittest
from unittest.mock import AsyncMock, patch

from scanner.env_detector import (
    is_env_template_filename,
    is_committed_env_filename,
    is_placeholder_value,
    inspect_env_file_content,
    is_source_code_file,
    is_sensitive_config_file,
    classify_file_for_remediation,
)
from remediation import propose_remediation_patch
from starlette.testclient import TestClient
from main import app, generate_session_token


class TestEnvDetector(unittest.TestCase):
    """Test suite for environment file classification and content inspection."""

    def test_is_source_code_file(self):
        """Verify source-code files are distinguished from config files."""
        source_files = [
            "challenge/labs/business_logic_lab/app.py",
            "server.ts",
            "app.js",
            "service/auth.go",
            "src/components/Modal.tsx",
            "Main.java",
            "Worker.cs",
            "index.php",
            "script.rb",
        ]
        for sf in source_files:
            self.assertTrue(is_source_code_file(sf), f"Expected {sf} to be identified as source code")

        non_source = [
            ".env",
            "backend/.env",
            ".env.example",
            "id_rsa",
            "cert.pem",
            "service-account.json",
            "credentials.json",
            "README.md",
            ".gitignore",
        ]
        for nsf in non_source:
            self.assertFalse(is_source_code_file(nsf), f"Expected {nsf} NOT to be identified as source code")

    def test_is_sensitive_config_file(self):
        """Verify sensitive configuration files are distinguished from ordinary source code and templates."""
        sensitive_files = [
            ".env",
            "backend/.env",
            ".env.production",
            ".env.local",
            "id_rsa",
            "id_ed25519",
            "deploy_key.pem",
            "server.key",
            "service-account.json",
            "gcp-service-account-key.json",
            "credentials.json",
            "token.json",
            ".npmrc",
            ".pypirc",
        ]
        for s_file in sensitive_files:
            self.assertTrue(is_sensitive_config_file(s_file), f"Expected {s_file} to be sensitive config")

        not_sensitive = [
            "challenge/labs/business_logic_lab/app.py",
            "settings.py",
            "main.go",
            "server.ts",
            ".env.example",
            "backend/.env.example",
            ".env.sample",
            ".env.template",
            "README.md",
            "package.json",
            "requirements.txt",
        ]
        for ns_file in not_sensitive:
            self.assertFalse(is_sensitive_config_file(ns_file), f"Expected {ns_file} NOT to be sensitive config")

    def test_classify_file_for_remediation(self):
        """Verify file classification maps correctly to remediation categories."""
        self.assertEqual(
            classify_file_for_remediation("challenge/labs/business_logic_lab/app.py"),
            "source_code"
        )
        self.assertEqual(
            classify_file_for_remediation("backend/.env"),
            "sensitive_config"
        )
        self.assertEqual(
            classify_file_for_remediation("backend/.env.example"),
            "env_template"
        )
        self.assertEqual(
            classify_file_for_remediation("id_rsa"),
            "sensitive_config"
        )

    def test_is_env_template_filename(self):
        """Verify template filenames are correctly identified."""
        templates = [
            ".env.example",
            "backend/.env.example",
            "frontend/.env.sample",
            "config/.env.template",
            ".env.dist",
            ".env.defaults",
            "example.env",
            "sample.env",
            "template.env",
            "app.env.example",
        ]
        for t in templates:
            self.assertTrue(is_env_template_filename(t), f"Expected {t} to be recognized as template")

        non_templates = [
            ".env",
            "backend/.env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.staging",
            "app.py",
            "main.js",
        ]
        for nt in non_templates:
            self.assertFalse(is_env_template_filename(nt), f"Expected {nt} NOT to be a template")

    def test_is_committed_env_filename(self):
        """Verify runtime committed .env filenames are correctly identified."""
        runtime_envs = [
            ".env",
            "backend/.env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.staging",
        ]
        for re_file in runtime_envs:
            self.assertTrue(is_committed_env_filename(re_file), f"Expected {re_file} to be runtime env")

        non_runtime = [
            ".env.example",
            "backend/.env.example",
            ".env.sample",
            ".env.template",
            "settings.py",
            "package.json",
        ]
        for nr in non_runtime:
            self.assertFalse(is_committed_env_filename(nr), f"Expected {nr} NOT to be runtime env")

    def test_placeholder_value_detection(self):
        """Verify placeholder values are detected and not treated as exposed secrets."""
        placeholders = [
            "YOUR_API_KEY",
            "your-api-key-here",
            "CHANGE_ME",
            "change_me",
            "replace_me_with_secret",
            "<your_token_here>",
            "[YOUR_SECRET]",
            "{INSERT_KEY}",
            "dummy_secret",
            "fake_token",
            "your-random-strong-secret-token",
            "your_secret_key_here",
            "localhost",
            "127.0.0.1",
            "postgres://user:password@localhost:5432/db",
            "mongodb://localhost:27017/vibesec",
            "",
            "   ",
            "true",
            "false",
            "test",
            "development",
            "default",
        ]
        for p in placeholders:
            self.assertTrue(is_placeholder_value(p), f"Expected '{p}' to be recognized as placeholder")

        real_secrets = [
            "sk-proj-abc1234567890abcdef1234567890",
            "ghp_1234567890abcdef1234567890abcdef123456",
            "AKIA1234567890ABCDEF",
            "super_secret_production_password_2026!#",
            "db_pass_prod_99x_unique",
        ]
        for s in real_secrets:
            self.assertFalse(is_placeholder_value(s), f"Expected '{s}' NOT to be recognized as placeholder")

    def test_safe_env_example_produces_zero_findings(self):
        """backend/.env.example containing placeholder values should produce 0 vulnerabilities."""
        safe_example = """# VibeSec Environment Example
PORT=8000
ENVIRONMENT=development
JWT_SECRET=your-random-32-byte-hex-string-change-this-in-production
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_PROXY_TOKEN=your-random-strong-secret-token
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
DATABASE_URL=postgres://user:password@localhost:5432/vibesec
GITHUB_TOKEN=
"""
        findings = inspect_env_file_content(safe_example, "backend/.env.example")
        self.assertEqual(findings, [], "Safe .env.example with placeholders must produce 0 findings")

    def test_env_template_with_real_secret_is_reported(self):
        """If .env.example or template contains a real credential, it must be reported."""
        leaked_template = """# Example env with accidental leak
PORT=8000
OPENAI_API_KEY=sk-proj123456789012345678901234567890
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789
NORMAL_PLACEHOLDER=YOUR_NORMAL_KEY
"""
        findings = inspect_env_file_content(leaked_template, ".env.example")
        self.assertGreaterEqual(len(findings), 1, "Template with real secrets must produce findings")
        first = findings[0]
        self.assertIn("Exposed Credential in Environment Template", first["title"])
        self.assertEqual(first["severity"], "critical")
        self.assertEqual(first["file"], ".env.example")

    def test_committed_runtime_env_with_real_secret_is_reported(self):
        """Committed .env containing real credentials must be reported with snippet evidence."""
        committed_env = """DATABASE_PASSWORD=supersecret_pass123
SECRET_KEY=99f8d7b6a5c4e3d2c1b0a9f8e7d6c5b4
JWT_SECRET=real_jwt_secret_value_not_placeholder
"""
        findings = inspect_env_file_content(committed_env, "backend/.env")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["title"], "Committed Sensitive Environment File (.env)")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["file"], "backend/.env")
        self.assertIn("Line 1", finding["code_snippet"])

    def test_committed_runtime_env_with_only_placeholders_not_flagged_as_live_secret(self):
        """Committed .env that has only empty or placeholder values should not report live secrets."""
        dummy_env = """PORT=3000
DEBUG=true
API_KEY=YOUR_API_KEY
DATABASE_URL=mongodb://localhost:27017/dev
"""
        findings = inspect_env_file_content(dummy_env, ".env")
        self.assertEqual(findings, [])


class TestFileLevelRemediation(unittest.IsolatedAsyncioTestCase):
    """Test AI Fix & Verify handling for file-level findings and source code credentials."""

    async def test_propose_patch_for_source_code_finding_preserves_file(self):
        """A credential finding in challenge/labs/business_logic_lab/app.py must NEVER recommend git rm --cached or .gitignore."""
        vuln = {
            "title": "Hardcoded API Token / Secret Credentials",
            "severity": "critical",
            "file": "challenge/labs/business_logic_lab/app.py",
            "description": "Hardcoded API key detected in source code.",
            "rule_id": "CWE-798"
        }
        res = await propose_remediation_patch(
            vulnerability=vuln,
            code="",
            language="python",
            filename="challenge/labs/business_logic_lab/app.py"
        )
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("is_file_level"))
        self.assertEqual(res.get("remediation_category"), "source_code")

        # Verify steps explicitly instruct preserving file in Git
        steps = res.get("remediation_steps", [])
        steps_text = " ".join(steps)
        self.assertIn("Keep 'challenge/labs/business_logic_lab/app.py' tracked in Git", steps_text)
        self.assertIn("Never remove application source files from Git tracking", steps_text)
        self.assertIn("os.getenv", steps_text)
        self.assertIn("rotate", steps_text.lower())
        self.assertIn("git-filter-repo", steps_text)

        # Verify commands NEVER recommend git rm --cached on app.py or adding app.py to .gitignore
        commands = res.get("recommended_commands", [])
        commands_str = " ".join(commands)
        self.assertNotIn("git rm --cached", commands_str)
        self.assertNotIn('.gitignore"', commands_str)
        self.assertIn("KEEP 'app.py' tracked in Git", commands_str)
        self.assertIn("echo \"API_KEY=your_actual_key_here\" >> .env", commands_str)
        self.assertIn("git-filter-repo", commands_str)

    async def test_propose_patch_for_sensitive_config_untracks_file(self):
        """When code is empty for a committed .env finding, propose_remediation_patch should recommend git rm --cached."""
        vuln = {
            "title": "Committed Sensitive Environment File (.env)",
            "severity": "critical",
            "file": "backend/.env",
            "description": "Environment credentials file committed to public version control.",
            "fix": "Remove file from repository history with git-filter-repo and append .env to .gitignore."
        }
        res = await propose_remediation_patch(
            vulnerability=vuln,
            code="",
            language="bash",
            filename="backend/.env"
        )
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("is_file_level"))
        self.assertEqual(res.get("remediation_category"), "sensitive_config")
        self.assertIn(res.get("remediation_type"), ("sensitive_file_untrack", "actionable_instructions"))
        self.assertIn("remediation_steps", res)
        self.assertGreater(len(res["remediation_steps"]), 0)
        self.assertIn("recommended_commands", res)
        # Verify recommended commands contain git rm --cached backend/.env
        commands_str = " ".join(res["recommended_commands"])
        self.assertIn("git rm --cached backend/.env", commands_str)
        self.assertIn('.gitignore', commands_str)

    async def test_propose_patch_for_template_file_preserves_template(self):
        """A finding in .env.example must recommend replacing secrets with placeholders and NOT untracking."""
        vuln = {
            "title": "Exposed Credential in Environment Template",
            "severity": "critical",
            "file": "backend/.env.example",
            "description": "Live API key committed in template file."
        }
        res = await propose_remediation_patch(
            vulnerability=vuln,
            code="",
            language="bash",
            filename="backend/.env.example"
        )
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("is_file_level"))
        self.assertEqual(res.get("remediation_category"), "env_template")
        commands_str = " ".join(res.get("recommended_commands", []))
        self.assertNotIn("git rm --cached", commands_str)
        self.assertIn("git add backend/.env.example", commands_str)

    def test_api_propose_patch_source_file_empty_code(self):
        """API /api/remediate/propose-patch should return category source_code for app.py without code snippet."""
        client = TestClient(app)
        session_id = "test-source-session"
        token = generate_session_token(session_id)
        headers = {
            "X-Session-ID": session_id,
            "X-Session-Token": token,
            "Content-Type": "application/json"
        }
        payload = {
            "vulnerability": {
                "title": "Hardcoded API Token / Secret Credentials",
                "severity": "critical",
                "file": "challenge/labs/business_logic_lab/app.py",
                "description": "Exposed secret in app.py"
            },
            "code": "",
            "language": "python",
            "filename": "challenge/labs/business_logic_lab/app.py"
        }
        response = client.post("/api/remediate/propose-patch", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("is_file_level"))
        self.assertEqual(data.get("remediation_category"), "source_code")
        commands_str = " ".join(data.get("recommended_commands", []))
        self.assertNotIn("git rm --cached", commands_str)
        self.assertIn("KEEP 'app.py' tracked in Git", commands_str)

    def test_api_propose_patch_endpoint_with_empty_code(self):
        """API /api/remediate/propose-patch should return 200 with instructions for file-level finding with empty code."""
        client = TestClient(app)
        session_id = "test-env-session"
        token = generate_session_token(session_id)
        headers = {
            "X-Session-ID": session_id,
            "X-Session-Token": token,
            "Content-Type": "application/json"
        }
        payload = {
            "vulnerability": {
                "title": "Committed Sensitive Environment File (.env)",
                "severity": "critical",
                "file": "backend/.env",
                "description": "Active environment credentials file committed to source control."
            },
            "code": "",
            "language": "bash",
            "filename": "backend/.env"
        }
        response = client.post("/api/remediate/propose-patch", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("is_file_level"))
        self.assertEqual(data.get("remediation_category"), "sensitive_config")
        self.assertIn("remediation_steps", data)
        self.assertIn("recommended_commands", data)



if __name__ == "__main__":
    unittest.main()
