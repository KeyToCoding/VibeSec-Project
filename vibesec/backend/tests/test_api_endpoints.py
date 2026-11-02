"""
FastAPI Endpoint Integration Tests for AI Fix & Verify Remediation
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import unittest
from unittest.mock import patch, AsyncMock
import json
from fastapi.testclient import TestClient

from main import app, generate_session_token
from remediation import VERIFICATION_STATE_VERIFIED, VERIFICATION_STATE_FAILED, VERIFICATION_STATE_STILL_DETECTED

client = TestClient(app)


class TestRemediationEndpoints(unittest.TestCase):

    def setUp(self):
        self.vuln_payload = {
            "title": "Command Injection via Shell Execution",
            "severity": "critical",
            "owasp": "A03:2021-Injection",
            "rule_id": "vibesec.cmdi.subprocess-shell",
            "line_hint": 3,
            "description": "Shell=True enables arbitrary command execution.",
            "code_snippet": "subprocess.run(cmd, shell=True)"
        }
        self.code = "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
        self.fixed_code = "import subprocess, shlex\ndef run(cmd):\n    args = shlex.split(cmd)\n    subprocess.run(args, shell=False)\n"

    @patch("remediation.call_llm", new_callable=AsyncMock)
    def test_api_propose_patch_success(self, mock_call_llm):
        mock_call_llm.return_value = (json.dumps({
            "explanation": "Set shell=False and pass parsed argument list with shlex.",
            "patched_code": self.fixed_code,
            "changes_summary": ["Disabled shell execution", "Safely tokenized command"],
            "security_caveats": "Validate allowed executable paths"
        }), "Ollama (qwen2.5-coder:7b)")

        response = client.post("/api/remediate/propose-patch", json={
            "vulnerability": self.vuln_payload,
            "code": self.code,
            "language": "python",
            "filename": "cmd_runner.py"
        })

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("patched_code"), self.fixed_code)
        self.assertIn("--- a/cmd_runner.py", data.get("unified_diff", ""))
        self.assertIn("+++ b/cmd_runner.py", data.get("unified_diff", ""))

    def test_api_propose_patch_empty_code_rejected(self):
        response = client.post("/api/remediate/propose-patch", json={
            "vulnerability": self.vuln_payload,
            "code": "   ",
            "language": "python"
        })
        self.assertEqual(response.status_code, 400)

    def test_api_verify_patch_requires_approval(self):
        # Explicit approval is FALSE -> must reject with 400
        response = client.post("/api/remediate/verify-patch", json={
            "original_code": self.code,
            "patched_code": self.fixed_code,
            "vulnerability": self.vuln_payload,
            "language": "python",
            "user_approved": False
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("approval", response.json().get("detail", "").lower())

    def test_api_verify_patch_success_with_approval(self):
        # Explicit approval is TRUE -> returns verification result
        response = client.post("/api/remediate/verify-patch", json={
            "original_code": self.code,
            "patched_code": self.fixed_code,
            "vulnerability": self.vuln_payload,
            "language": "python",
            "user_approved": True
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("verification_state"), VERIFICATION_STATE_VERIFIED)
        self.assertTrue(data.get("verified"))
        self.assertIn("Passing static checks does not prove the code is completely secure", data.get("disclaimer", ""))

    def test_api_verify_patch_still_detected(self):
        bad_patch = "import os\ndef run(cmd):\n    os.system(cmd)\n"
        response = client.post("/api/remediate/verify-patch", json={
            "original_code": self.code,
            "patched_code": bad_patch,
            "vulnerability": self.vuln_payload,
            "language": "python",
            "user_approved": True
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("verification_state"), VERIFICATION_STATE_STILL_DETECTED)
        self.assertFalse(data.get("verified"))

    def test_healthz_endpoint(self):
        response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data.get("service"), "vibesec-backend")

    def test_internal_token_protection(self):
        import os
        token = "test-secret-internal-token-12345"
        with patch.dict(os.environ, {"FASTAPI_INTERNAL_TOKEN": token}):
            # Health check is public
            healthz_resp = client.get("/healthz")
            self.assertEqual(healthz_resp.status_code, 200)

            # Protected endpoint without token -> 401
            unauth_resp = client.get("/api/history")
            self.assertEqual(unauth_resp.status_code, 401)

            # Protected endpoint with invalid token -> 401
            invalid_resp = client.get("/api/history", headers={"x-internal-token": "wrong"})
            self.assertEqual(invalid_resp.status_code, 401)

            # Protected endpoint with valid x-internal-token header -> 200
            auth_resp = client.get("/api/history", headers={"x-internal-token": token})
            self.assertEqual(auth_resp.status_code, 200)

            # Protected endpoint with Bearer authorization header -> 200
            bearer_resp = client.get("/api/history", headers={"authorization": f"Bearer {token}"})
            self.assertEqual(bearer_resp.status_code, 200)

    def test_session_history_isolation(self):
        token_a = generate_session_token("session-user-a")
        headers_a = {"x-session-id": "session-user-a", "x-session-token": token_a}
        token_b = generate_session_token("session-user-b")
        headers_b = {"x-session-id": "session-user-b", "x-session-token": token_b}

        # Scan under session A
        res_a = client.post(
            "/api/scan/code",
            json={"code": "x = 1\n", "language": "python", "filename": "a.py"},
            headers=headers_a
        )
        self.assertEqual(res_a.status_code, 200)
        scan_a_id = res_a.json().get("scan_id")
        self.assertEqual(res_a.json().get("session_id"), "session-user-a")

        # Scan under session B
        res_b = client.post(
            "/api/scan/code",
            json={"code": "y = 2\n", "language": "python", "filename": "b.py"},
            headers=headers_b
        )
        self.assertEqual(res_b.status_code, 200)
        scan_b_id = res_b.json().get("scan_id")
        self.assertEqual(res_b.json().get("session_id"), "session-user-b")

        # Retrieve history for session A
        hist_a_resp = client.get("/api/history", headers=headers_a)
        self.assertEqual(hist_a_resp.status_code, 200)
        hist_a = hist_a_resp.json()
        self.assertIsInstance(hist_a, list)
        self.assertGreater(len(hist_a), 0)
        for item in hist_a:
            self.assertEqual(item.get("session_id"), "session-user-a")

        # Retrieve history for session B
        hist_b_resp = client.get("/api/history", headers=headers_b)
        self.assertEqual(hist_b_resp.status_code, 200)
        hist_b = hist_b_resp.json()
        self.assertIsInstance(hist_b, list)
        self.assertGreater(len(hist_b), 0)
        for item in hist_b:
            self.assertEqual(item.get("session_id"), "session-user-b")

        # Session A cannot access Session B's scan report by ID
        unauth_scan_b = client.get(f"/api/scan/{scan_b_id}", headers=headers_a)
        self.assertEqual(unauth_scan_b.status_code, 403)

        # Session A can access its own scan report by ID
        auth_scan_a = client.get(f"/api/scan/{scan_a_id}", headers=headers_a)
        self.assertEqual(auth_scan_a.status_code, 200)

        # Unauthenticated request without token is rejected
        unauth_hist = client.get("/api/history", headers={"x-session-id": "session-user-a"})
        self.assertEqual(unauth_hist.status_code, 401)

        # Request with forged / invalid token is rejected
        forged_hist = client.get("/api/history", headers={"x-session-id": "session-user-a", "x-session-token": "bad-token"})
        self.assertEqual(forged_hist.status_code, 401)

    def test_missing_credentials_access_control(self):
        """Requests with missing credentials cannot view session reports or history."""
        # Clean history query with no session returns empty list
        resp = client.get("/api/history")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

        # Non-existent scan report returns 404
        resp_404 = client.get("/api/scan/nonexistent-uuid-00000")
        self.assertEqual(resp_404.status_code, 404)

        # Create a scan under a private session
        tok = generate_session_token("private-user-1")
        scan_resp = client.post(
            "/api/scan/code",
            json={"code": "val = 42\n", "language": "python", "filename": "priv.py"},
            headers={"x-session-id": "private-user-1", "x-session-token": tok}
        )
        self.assertEqual(scan_resp.status_code, 200)
        scan_id = scan_resp.json().get("scan_id")

        # Anonymous request without any session headers to this scan report is rejected with 401
        anon_resp = client.get(f"/api/scan/{scan_id}")
        self.assertEqual(anon_resp.status_code, 401)
        self.assertIn("authentication required", anon_resp.json().get("detail", "").lower())

    def test_forged_and_tampered_credentials_rejected(self):
        """Forged signatures, tampered tokens, and session mismatch attacks must fail."""
        # Create a legitimate scan under victim session
        victim_sid = "victim-account-99"
        victim_tok = generate_session_token(victim_sid)
        scan_resp = client.post(
            "/api/scan/code",
            json={"code": "secret_key = 'demo'\n", "language": "python", "filename": "sec.py"},
            headers={"x-session-id": victim_sid, "x-session-token": victim_tok}
        )
        self.assertEqual(scan_resp.status_code, 200)
        scan_id = scan_resp.json().get("scan_id")

        # Attack 1: Guessed X-Session-ID with completely forged HMAC signature
        resp1 = client.get(
            "/api/history",
            headers={"x-session-id": victim_sid, "x-session-token": "deadbeef1234567890abcdef"}
        )
        self.assertEqual(resp1.status_code, 401)

        # Attack 2: Valid token of another session supplied with victim's session ID (token transposition)
        attacker_sid = "attacker-account-66"
        attacker_tok = generate_session_token(attacker_sid)
        resp2 = client.get(
            "/api/history",
            headers={"x-session-id": victim_sid, "x-session-token": attacker_tok}
        )
        self.assertEqual(resp2.status_code, 401)

        # Attack 3: Forged Authorization: Session header
        resp3 = client.get(
            "/api/history",
            headers={"authorization": f"Session {victim_sid}.invalidhmacsignature99"}
        )
        self.assertEqual(resp3.status_code, 401)

        # Attack 4: Forged token accessing scan report by scan ID
        resp4 = client.get(
            f"/api/scan/{scan_id}",
            headers={"x-session-id": victim_sid, "x-session-token": "tampered-token"}
        )
        self.assertEqual(resp4.status_code, 401)

    def test_query_parameter_credential_security(self):
        """Session credentials passed via query parameters are validated strictly."""
        sid = "query-param-user"
        tok = generate_session_token(sid)

        # Create scan for this user
        scan_resp = client.post(
            "/api/scan/code",
            json={"code": "z = 100\n", "language": "python"},
            headers={"x-session-id": sid, "x-session-token": tok}
        )
        self.assertEqual(scan_resp.status_code, 200)
        scan_id = scan_resp.json().get("scan_id")

        # Query param session_id without session_token is rejected with 401
        resp_unauth = client.get(f"/api/history?session_id={sid}")
        self.assertEqual(resp_unauth.status_code, 401)

        # Query param session_id with forged session_token is rejected with 401
        resp_forged = client.get(f"/api/history?session_id={sid}&session_token=fake-token-xyz")
        self.assertEqual(resp_forged.status_code, 401)

        # Query param with valid session_id and session_token succeeds with 200
        resp_valid = client.get(f"/api/history?session_id={sid}&session_token={tok}")
        self.assertEqual(resp_valid.status_code, 200)
        hist = resp_valid.json()
        self.assertIsInstance(hist, list)
        self.assertGreater(len(hist), 0)
        self.assertEqual(hist[0].get("session_id"), sid)

        # Query param scan retrieval without token is rejected with 401
        scan_unauth = client.get(f"/api/scan/{scan_id}?session_id={sid}")
        self.assertEqual(scan_unauth.status_code, 401)

        # Query param scan retrieval with valid credentials succeeds with 200
        scan_valid = client.get(f"/api/scan/{scan_id}?session_id={sid}&session_token={tok}")
        self.assertEqual(scan_valid.status_code, 200)
        self.assertEqual(scan_valid.json().get("scan_id"), scan_id)

        # Cross-session query param access: user B cannot read user A's scan
        other_sid = "other-query-user"
        other_tok = generate_session_token(other_sid)
        cross_resp = client.get(f"/api/scan/{scan_id}?session_id={other_sid}&session_token={other_tok}")
        self.assertEqual(cross_resp.status_code, 403)

    def test_session_issuance_and_signature_consistency(self):
        """The /api/session endpoint safely issues unguessable sessions and re-verifies authentic sessions."""
        # Call /api/session without any credentials -> issues new session vs_*
        issue_resp = client.get("/api/session")
        self.assertEqual(issue_resp.status_code, 200)
        data = issue_resp.json()
        new_sid = data.get("session_id")
        new_tok = data.get("session_token")
        self.assertTrue(new_sid.startswith("vs_"))
        self.assertIn(".", new_tok)
        self.assertEqual(issue_resp.headers.get("X-Session-ID"), new_sid)
        self.assertEqual(issue_resp.headers.get("X-Session-Token"), new_tok)

        # Re-verify the issued session -> confirms authentication
        verify_resp = client.get("/api/session", headers={"x-session-id": new_sid, "x-session-token": new_tok})
        self.assertEqual(verify_resp.status_code, 200)
        self.assertEqual(verify_resp.json().get("session_id"), new_sid)

        # Call with forged session ID -> ignores client forged ID and issues a clean new vs_* session
        forged_req = client.get("/api/session", headers={"x-session-id": "admin-account", "x-session-token": "forged-token"})
        self.assertEqual(forged_req.status_code, 200)
        forged_data = forged_req.json()
        self.assertNotEqual(forged_data.get("session_id"), "admin-account")
        self.assertTrue(forged_data.get("session_id").startswith("vs_"))


if __name__ == "__main__":
    unittest.main()
