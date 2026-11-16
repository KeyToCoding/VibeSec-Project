"""
Unit tests for VibeSec URL Scanner validation, SSRF protection,
Pydantic payload normalization, and FastAPI endpoint compatibility.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
import httpx

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app, UrlScanRequest
from scanner.url_scanner import is_safe_public_url, scan_url

client = TestClient(app)


class TestUrlScannerValidation(unittest.TestCase):
    """Test URL schema, validation, and SSRF filtering."""

    def test_empty_url_rejected_by_pydantic(self):
        req = UrlScanRequest.model_validate({"url": ""})
        self.assertEqual(req.url, None)
        self.assertEqual(req.target_url, None)

    def test_whitespace_only_url_rejected_by_pydantic(self):
        req = UrlScanRequest.model_validate({"url": "   \t\n  "})
        self.assertEqual(req.url, None)

    def test_target_url_compatibility(self):
        # Frontend sending target_url must resolve to url
        req = UrlScanRequest.model_validate({"target_url": "https://testphp.vulnweb.com/"})
        self.assertEqual(req.url, "https://testphp.vulnweb.com/")
        self.assertEqual(req.target_url, "https://testphp.vulnweb.com/")

    def test_scan_url_alias_compatibility(self):
        req = UrlScanRequest.model_validate({"scan_url": "https://demo.owasp-juice.shop"})
        self.assertEqual(req.url, "https://demo.owasp-juice.shop")

    def test_whitespace_trimmed_by_schema(self):
        req = UrlScanRequest.model_validate({"url": "  https://example.com/  "})
        self.assertEqual(req.url, "https://example.com/")

    def test_ssrf_localhost_blocked(self):
        is_safe, msg, _ = is_safe_public_url("http://127.0.0.1:8000/api")
        self.assertFalse(is_safe)
        self.assertIn("SSRF Protection", msg)

    def test_ssrf_metadata_ip_blocked(self):
        is_safe, msg, _ = is_safe_public_url("http://169.254.169.254/latest/meta-data")
        self.assertFalse(is_safe)
        self.assertIn("SSRF Protection", msg)

    def test_ssrf_invalid_protocol_blocked(self):
        is_safe, msg, _ = is_safe_public_url("ftp://example.com/file")
        self.assertFalse(is_safe)
        self.assertIn("Only HTTP and HTTPS", msg)

    def test_ssrf_missing_hostname_blocked(self):
        is_safe, msg, _ = is_safe_public_url("https://")
        self.assertFalse(is_safe)
        self.assertIn("missing hostname", msg.lower())


class TestUrlScannerEndpoint(unittest.TestCase):
    """Test FastAPI /api/scan/url with mocked network responses."""

    def test_endpoint_empty_url_rejected(self):
        res = client.post("/api/scan/url", json={"url": ""})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Valid URL must be specified", res.json().get("detail", ""))

    def test_endpoint_whitespace_url_rejected(self):
        res = client.post("/api/scan/url", json={"url": "   "})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Valid URL must be specified", res.json().get("detail", ""))

    def test_endpoint_empty_payload_rejected(self):
        res = client.post("/api/scan/url", json={})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Valid URL must be specified", res.json().get("detail", ""))

    def test_endpoint_ssrf_rejected(self):
        res = client.post("/api/scan/url", json={"url": "http://127.0.0.1:8000"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("SSRF Protection", res.json().get("detail", ""))

    @patch("scanner.url_scanner.httpx.AsyncClient")
    def test_endpoint_valid_url_with_url_key(self, mock_client_cls):
        # Mock httpx response
        mock_resp = MagicMock()
        mock_resp.url = httpx.URL("https://example.com")
        mock_resp.headers = {
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        }
        mock_resp.cookies = {"session_token": "dummy_cookie_value"}
        mock_resp.text = "<html><head></head><body><h1>Hello</h1></body></html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client_cls.return_value = mock_client

        res = client.post("/api/scan/url", json={"url": "https://example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("input_type"), "url")
        self.assertEqual(data.get("target_url"), "https://example.com")
        self.assertIn("vulnerabilities", data)
        self.assertIn("severity_counts", data)
        self.assertIn("header_status", data)
        self.assertIn("X-Session-ID", res.headers)

    @patch("scanner.url_scanner.httpx.AsyncClient")
    def test_endpoint_valid_url_with_target_url_key(self, mock_client_cls):
        # Frontend payload compatibility: {"target_url": "https://example.com"}
        mock_resp = MagicMock()
        mock_resp.url = httpx.URL("https://example.com")
        mock_resp.headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
        }
        mock_resp.cookies = {}
        mock_resp.text = "<html><body>Clean</body></html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client_cls.return_value = mock_client

        res = client.post("/api/scan/url", json={"target_url": "https://example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("input_type"), "url")
        self.assertEqual(data.get("target_url"), "https://example.com")


if __name__ == "__main__":
    unittest.main()
