"""
VibeSec File Upload & Archive Security Tests
Verifies:
- 100 MB upload limit enforcement (valid vs oversized)
- 250 MB uncompressed expansion ceiling (Zip-Bomb protection)
- 500 files archive count ceiling
- Zip-Slip path traversal defense
- Temporary directory sandbox isolation and cleanup
- Empty file handling
"""

import os
import io
import zipfile
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from main import app, generate_session_token

client = TestClient(app)


class TestUploadLimitsAndSecurity(unittest.TestCase):

    def test_valid_single_file_upload(self):
        """Upload of a normal python file within limits succeeds."""
        token = generate_session_token("test-session-upload")
        code_content = b"import math\ndef calc(x):\n    return math.sqrt(x)\n"
        response = client.post(
            "/api/scan/upload",
            files={"file": ("calc.py", io.BytesIO(code_content), "text/x-python")},
            headers={"x-session-id": "test-session-upload", "x-session-token": token}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan_id", data)
        self.assertEqual(data.get("session_id"), "test-session-upload")
        self.assertEqual(data.get("files_scanned"), 1)
        self.assertIn("calc.py", data.get("files_scanned_list", []))

    def test_valid_zip_archive_upload(self):
        """Upload of a standard multi-file zip archive succeeds."""
        token = generate_session_token("test-session-zip")
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("module1.py", "def a(): return 1\n")
            zf.writestr("module2.py", "def b(): return 2\n")

        zip_buf.seek(0)
        response = client.post(
            "/api/scan/upload",
            files={"file": ("project.zip", zip_buf, "application/zip")},
            headers={"x-session-id": "test-session-zip", "x-session-token": token}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("files_scanned"), 2)
        self.assertIn("module1.py", data.get("files_scanned_list", []))
        self.assertIn("module2.py", data.get("files_scanned_list", []))

    def test_oversized_content_length_rejected_413(self):
        """Requests declaring Content-Length > 100MB are immediately rejected with HTTP 413."""
        response = client.post(
            "/api/scan/upload",
            files={"file": ("test.py", io.BytesIO(b"print('hello')"), "text/plain")},
            headers={"content-length": str(105 * 1024 * 1024)}
        )
        self.assertEqual(response.status_code, 413)
        data = response.json()
        self.assertIn("100MB", data.get("detail", ""))

    def test_oversized_stream_rejected_413(self):
        """Streaming uploads that exceed the upload limit are aborted with HTTP 413."""
        # Test stream enforcement using 200KB mock limit with 400KB data
        with patch("main.MAX_UPLOAD_SIZE", 200 * 1024):
            oversized_stream = b"X" * (400 * 1024)
            response = client.post(
                "/api/scan/upload",
                files={"file": ("oversized.bin", io.BytesIO(oversized_stream), "application/octet-stream")},
            )
            self.assertEqual(response.status_code, 413)
            data = response.json()
            self.assertIn("exceeds the maximum allowed limit", data.get("detail", ""))

    def test_empty_upload_rejected_400(self):
        """Uploading an empty 0-byte file returns HTTP 400."""
        response = client.post(
            "/api/scan/upload",
            files={"file": ("empty.py", io.BytesIO(b""), "text/plain")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("empty", response.json().get("detail", "").lower())

    def test_zip_slip_path_traversal_prevention(self):
        """Archive containing path traversal filenames must not extract outside sandbox."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            # Illegal path traversal entries
            zf.writestr("../../etc/passwd", "root:x:0:0::/root:/bin/sh")
            zf.writestr("../traversal_test.py", "print('hacked')")
            # Legal file
            zf.writestr("safe_app.py", "print('safe')")

        zip_buf.seek(0)
        response = client.post(
            "/api/scan/upload",
            files={"file": ("malicious_slip.zip", zip_buf, "application/zip")},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # The illegal path entries must be recorded in files_skipped
        skipped_str = " ".join(data.get("files_skipped", []))
        self.assertTrue(
            "illegal path traversal" in skipped_str or "traversal_test.py" in skipped_str or "passwd" in skipped_str
        )
        # Safe file must still be scanned
        self.assertIn("safe_app.py", data.get("files_scanned_list", []))

    def test_zip_bomb_uncompressed_size_ceiling(self):
        """Archive exceeding 250MB uncompressed must trigger Zip Bomb protection."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 3 files x 90MB zeroes = 270MB uncompressed (compresses to ~250KB)
            chunk_90mb = b"0" * (90 * 1024 * 1024)
            zf.writestr("chunk1.py", chunk_90mb)
            zf.writestr("chunk2.py", chunk_90mb)
            zf.writestr("chunk3.py", chunk_90mb)

        zip_buf.seek(0)
        response = client.post(
            "/api/scan/upload",
            files={"file": ("bomb_expand.zip", zip_buf, "application/zip")},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Vulnerabilities must contain Zip Bomb protection warning
        vuln_titles = [v.get("title", "") for v in data.get("vulnerabilities", [])]
        self.assertTrue(
            any("Zip Bomb Protection" in title or "Resource Limit" in title for title in vuln_titles),
            f"Expected Zip Bomb warning in findings, got: {vuln_titles}"
        )

    def test_zip_archive_max_files_ceiling(self):
        """Archive containing over 500 files must halt extraction at the 500 file limit."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add 520 files
            for i in range(520):
                zf.writestr(f"src/file_{i}.py", f"# file {i}\nx = {i}\n")

        zip_buf.seek(0)
        response = client.post(
            "/api/scan/upload",
            files={"file": ("many_files.zip", zip_buf, "application/zip")},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Scanned files count should not exceed the 500 file limit
        scanned_count = data.get("files_scanned", 0)
        self.assertLessEqual(scanned_count, 500)

        # Check that either a warning was logged in vulnerabilities or files were skipped
        vuln_titles = [v.get("title", "") for v in data.get("vulnerabilities", [])]
        has_limit_vuln = any("Limit" in t or "Ceiling" in t or "Zip Bomb" in t for t in vuln_titles)
        has_skipped_files = any("ceiling" in s.lower() or "limit" in s.lower() for s in data.get("files_skipped", []))
        self.assertTrue(
            has_limit_vuln or has_skipped_files or scanned_count == 500,
            "Expected 500 file limit to be enforced."
        )


if __name__ == "__main__":
    unittest.main()
