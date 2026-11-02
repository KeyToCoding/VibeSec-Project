"""Unit and integration tests for VibeSec GitHub Repository Scanner.
Verifies rate-limit handling, codeload archive fallback, error classification,
and zero fake vulnerabilities on API failures.
"""

import io
import os
import unittest
import zipfile
from unittest.mock import patch, MagicMock, AsyncMock

import httpx
from starlette.testclient import TestClient

from main import app, generate_session_token
from scanner.github_scanner import (
    scan_github,
    get_github_headers,
    extract_rate_limit_headers,
    parse_github_url,
    GitHubScanError,
    GitHubRateLimitError,
    GitHubNotFoundError,
    GitHubPermissionError,
    _GITHUB_CACHE,
)


def _create_mock_repo_zip() -> bytes:
    """Create a minimal in-memory zip file mimicking GitHub codeload archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Prefix root dir as GitHub archives do
        zf.writestr("Inventory-Management-System-HEAD/app.py", "eval(input('query: '))\n")
        zf.writestr("Inventory-Management-System-HEAD/.env", "DATABASE_PASSWORD=supersecret_pass123\n")
        zf.writestr("Inventory-Management-System-HEAD/node_modules/dep/index.js", "console.log('vendor');\n")
        zf.writestr("Inventory-Management-System-HEAD/logo.png", b"\x89PNG\r\n\x1a\nfake")
    return buf.getvalue()


class TestGitHubHeadersAndUrlValidation(unittest.TestCase):
    """Test header generation, rate-limit extraction, and URL validation."""

    def test_github_headers_default(self):
        with patch.dict(os.environ, {}, clear=True):
            headers = get_github_headers()
            self.assertIn("Accept", headers)
            self.assertEqual(headers["Accept"], "application/vnd.github+json")
            self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")
            self.assertIn("VibeSec", headers["User-Agent"])
            self.assertNotIn("Authorization", headers)

    def test_github_headers_with_token(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_mock_token_abc123"}):
            headers = get_github_headers()
            self.assertEqual(headers["Authorization"], "Bearer ghp_mock_token_abc123")
            self.assertIn("VibeSec", headers["User-Agent"])

    def test_extract_rate_limit_headers(self):
        raw_headers = httpx.Headers({
            "x-ratelimit-limit": "60",
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1730000000",
            "retry-after": "120",
        })
        info = extract_rate_limit_headers(raw_headers)
        self.assertEqual(info["x-ratelimit-limit"], "60")
        self.assertEqual(info["x-ratelimit-remaining"], "0")
        self.assertEqual(info["x-ratelimit-reset"], "1730000000")
        self.assertEqual(info["retry-after"], "120")

    def test_url_validation_valid(self):
        owner, repo = parse_github_url("https://github.com/KeyToCoding/Inventory-Management-System")
        self.assertEqual(owner, "KeyToCoding")
        self.assertEqual(repo, "Inventory-Management-System")

        owner, repo = parse_github_url("https://github.com/torvalds/linux.git")
        self.assertEqual(owner, "torvalds")
        self.assertEqual(repo, "linux")

    def test_url_validation_invalid(self):
        invalid_urls = [
            "https://gitlab.com/KeyToCoding/Inventory-Management-System",
            "https://github.com/../traversal/repo",
            "https://github.com/KeyToCoding/repo;rm -rf",
            "not-a-url",
            "http://github.com/foo",
        ]
        for url in invalid_urls:
            with self.assertRaises(GitHubScanError):
                parse_github_url(url)


class TestGitHubScannerLogic(unittest.IsolatedAsyncioTestCase):
    """Test scanner async logic including archive fallback and error handling."""

    def setUp(self):
        _GITHUB_CACHE.clear()

    async def test_nonexistent_repo_404(self):
        """404 on repo lookup raises GitHubNotFoundError and NEVER creates a vulnerability finding."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 404
        mock_resp.headers = httpx.Headers({})
        mock_resp.text = '{"message": "Not Found"}'
        mock_resp.json.return_value = {"message": "Not Found"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp

            with self.assertRaises(GitHubNotFoundError) as ctx:
                await scan_github("https://github.com/KeyToCoding/NonExistent-Repo-XYZ")

            self.assertEqual(ctx.exception.status_code, 404)
            self.assertIn("was not found", str(ctx.exception))

    async def test_private_repo_permission_403(self):
        """403 on private repo (not rate-limited) raises GitHubPermissionError."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 403
        mock_resp.headers = httpx.Headers({"x-ratelimit-remaining": "50"})  # quota still available
        mock_resp.text = '{"message": "Must have push access to view repository"}'
        mock_resp.json.return_value = {"message": "Must have push access to view repository"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp

            with self.assertRaises(GitHubPermissionError) as ctx:
                await scan_github("https://github.com/KeyToCoding/Private-Repo")

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("is forbidden", str(ctx.exception))

    async def test_rate_limit_403_triggers_archive_fallback_success(self):
        """When GitHub API returns HTTP 403 (rate limited), scanner automatically falls back
        to public codeload archive download, parses files, and returns real scanned count.
        """
        # Step 1: Repo lookup returns 403 with rate limit headers
        repo_403_resp = MagicMock(spec=httpx.Response)
        repo_403_resp.status_code = 403
        repo_403_resp.headers = httpx.Headers({
            "x-ratelimit-limit": "60",
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1730000000",
            "retry-after": "60",
        })
        repo_403_resp.text = '{"message": "API rate limit exceeded for IP"}'
        repo_403_resp.json.return_value = {"message": "API rate limit exceeded for IP"}

        # Step 2: Codeload archive download returns HTTP 200 with the valid zip
        archive_zip_bytes = _create_mock_repo_zip()
        archive_resp = MagicMock(spec=httpx.Response)
        archive_resp.status_code = 200
        archive_resp.headers = httpx.Headers({
            "content-length": str(len(archive_zip_bytes)),
            "content-type": "application/zip",
        })
        archive_resp.content = archive_zip_bytes

        async def mock_get(url, **kwargs):
            if "api.github.com" in url:
                return repo_403_resp
            if "codeload.github.com" in url or "archive/HEAD.zip" in url:
                return archive_resp
            return MagicMock(status_code=404)

        mock_scan_code = AsyncMock(return_value={
            "vulnerabilities": [{
                "title": "Use of Insecure Function (eval)",
                "severity": "high",
                "owasp": "A03:2021-Injection",
                "description": "Direct eval invocation",
                "file": "app.py",
                "line_hint": 1,
                "confidence": "high",
                "fix": "Avoid dynamic code execution with eval().",
            }],
            "hallucinated_packages": [],
        })

        with patch("httpx.AsyncClient.get", side_effect=mock_get), \
             patch("scanner.github_scanner.scan_code", mock_scan_code):
            result = await scan_github("https://github.com/KeyToCoding/Inventory-Management-System")

        # Verify scan succeeded via archive download
        self.assertEqual(result["scan_method"], "archive_download")
        self.assertEqual(result["owner"], "KeyToCoding")
        self.assertEqual(result["repo"], "Inventory-Management-System")

        # Verify real scanned-file count (app.py and .env; node_modules vendor skipped; logo.png skipped)
        self.assertGreaterEqual(result["files_scanned"], 2)
        self.assertIn("app.py", [p.split("/")[-1] for p in result["files_scanned_list"]])

        # Verify NO fake API vulnerabilities were reported
        for v in result["vulnerabilities"]:
            self.assertNotEqual(v.get("title"), "GitHub API Query Issue")
            self.assertNotIn("GitHub API", v.get("title", ""))

        # Verify sensitive .env file was flagged as a real finding
        titles = [v.get("title") for v in result["vulnerabilities"]]
        self.assertTrue(any("Committed Sensitive Environment File" in t for t in titles))

    async def test_both_api_and_archive_rate_limited_raises_error(self):
        """When API is rate-limited and archive download fails, raises GitHubRateLimitError without fake vulns."""
        rate_limit_resp = MagicMock(spec=httpx.Response)
        rate_limit_resp.status_code = 403
        rate_limit_resp.headers = httpx.Headers({
            "x-ratelimit-remaining": "0",
            "retry-after": "60",
        })
        rate_limit_resp.text = '{"message": "rate limit exceeded"}'
        rate_limit_resp.json.return_value = {"message": "rate limit exceeded"}

        archive_fail_resp = MagicMock(spec=httpx.Response)
        archive_fail_resp.status_code = 429
        archive_fail_resp.headers = httpx.Headers({"retry-after": "60"})

        async def mock_get(url, **kwargs):
            if "api.github.com" in url:
                return rate_limit_resp
            return archive_fail_resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            with self.assertRaises(GitHubScanError) as ctx:
                await scan_github("https://github.com/KeyToCoding/Inventory-Management-System")

            self.assertIn(ctx.exception.status_code, [403, 429, 502])


class TestFastAPIGitHubEndpoint(unittest.TestCase):
    """Integration tests for FastAPI /api/scan/github route."""

    def setUp(self):
        self.client = TestClient(app)
        self.session_id = "test-session-github"
        self.session_token = generate_session_token(self.session_id)
        self.headers = {
            "X-Session-ID": self.session_id,
            "X-Session-Token": self.session_token,
            "X-Internal-Token": os.getenv("FASTAPI_INTERNAL_TOKEN", "default-dev-secret-replace-in-production"),
        }
        _GITHUB_CACHE.clear()

    def test_endpoint_invalid_url(self):
        resp = self.client.post(
            "/api/scan/github",
            json={"repo_url": "https://malicious.org/bad/repo"},
            headers=self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertTrue("detail" in data or "error" in data)
        # Ensure not reporting as a security finding
        self.assertNotIn("vulnerabilities", data)

    def test_endpoint_404_repository(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 404
        mock_resp.headers = httpx.Headers({})
        mock_resp.text = '{"message": "Not Found"}'
        mock_resp.json.return_value = {"message": "Not Found"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            resp = self.client.post(
                "/api/scan/github",
                json={"repo_url": "https://github.com/KeyToCoding/Definitely-Not-Found-12345"},
                headers=self.headers,
            )
            self.assertEqual(resp.status_code, 404)
            data = resp.json()
            self.assertTrue("detail" in data or "error" in data)
            self.assertNotIn("vulnerabilities", data)

    def test_endpoint_archive_fallback_success(self):
        repo_403_resp = MagicMock(spec=httpx.Response)
        repo_403_resp.status_code = 403
        repo_403_resp.headers = httpx.Headers({
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1730000000",
        })
        repo_403_resp.text = '{"message": "rate limit exceeded"}'
        repo_403_resp.json.return_value = {"message": "rate limit exceeded"}

        archive_zip_bytes = _create_mock_repo_zip()
        archive_resp = MagicMock(spec=httpx.Response)
        archive_resp.status_code = 200
        archive_resp.headers = httpx.Headers({
            "content-length": str(len(archive_zip_bytes)),
            "content-type": "application/zip",
        })
        archive_resp.content = archive_zip_bytes

        async def mock_get(url, **kwargs):
            if "api.github.com" in url:
                return repo_403_resp
            return archive_resp

        mock_scan_code = AsyncMock(return_value={
            "vulnerabilities": [{
                "title": "Use of Insecure Function (eval)",
                "severity": "high",
                "owasp": "A03:2021-Injection",
                "description": "Direct eval invocation",
                "file": "app.py",
                "line_hint": 1,
                "confidence": "high",
                "fix": "Avoid dynamic code execution with eval().",
            }],
            "hallucinated_packages": [],
        })

        with patch("httpx.AsyncClient.get", side_effect=mock_get), \
             patch("scanner.github_scanner.scan_code", mock_scan_code):
            resp = self.client.post(
                "/api/scan/github",
                json={"repo_url": "https://github.com/KeyToCoding/Inventory-Management-System"},
                headers=self.headers,
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("vulnerabilities", data)
            self.assertGreater(data["files_scanned"], 0)
            self.assertEqual(data["scan_method"], "archive_download")
            # Verify no fake vulnerabilities
            for v in data["vulnerabilities"]:
                self.assertNotEqual(v.get("title"), "GitHub API Query Issue")


if __name__ == "__main__":
    unittest.main()
