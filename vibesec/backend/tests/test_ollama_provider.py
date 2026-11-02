"""
Unit and Integration Tests for Ollama Provider, Proxy Security, and Streaming
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import os
import sys
import json
import asyncio
import unittest
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
import httpx
from fastapi.testclient import TestClient

# Ensure root scripts directory is importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from main import app
from models.llm_chain import (
    get_ollama_config,
    get_ollama_headers,
    call_llm,
    stream_ollama,
    LLMTimeoutError,
    LLMProviderError,
)
from scripts.ollama_proxy import is_path_allowed, check_auth

client = TestClient(app)


class TestOllamaConfiguration(unittest.TestCase):
    """Test environment configuration, proxy token headers, and URL parsing."""

    def test_default_config(self):
        with patch.dict(os.environ, {}, clear=True):
            base_url, model = get_ollama_config()
            self.assertEqual(base_url, "http://127.0.0.1:11434")
            self.assertEqual(model, "qwen2.5-coder:7b")

    def test_custom_tunnel_url_and_model(self):
        custom_env = {
            "OLLAMA_URL": "https://custom-tunnel.trycloudflare.com/api/generate",
            "OLLAMA_MODEL": "qwen2.5-coder:7b",
        }
        with patch.dict(os.environ, custom_env, clear=True):
            base_url, model = get_ollama_config()
            # Endpoint suffixes should be normalized away
            self.assertEqual(base_url, "https://custom-tunnel.trycloudflare.com")
            self.assertEqual(model, "qwen2.5-coder:7b")

    def test_proxy_token_injection(self):
        token = "test-secret-proxy-token-12345"
        with patch.dict(os.environ, {"OLLAMA_PROXY_TOKEN": token}, clear=True):
            headers = get_ollama_headers()
            self.assertEqual(headers.get("Authorization"), f"Bearer {token}")
            self.assertEqual(headers.get("X-Ollama-Proxy-Token"), token)
            self.assertEqual(headers.get("Content-Type"), "application/json")


class TestOllamaProxySecurity(unittest.TestCase):
    """Verify security rules implemented in scripts/ollama_proxy.py."""

    def test_allowed_endpoints(self):
        # Whitelisted safe inference endpoints
        self.assertTrue(is_path_allowed("GET", "/"))
        self.assertTrue(is_path_allowed("GET", "/api/tags"))
        self.assertTrue(is_path_allowed("GET", "/api/version"))
        self.assertTrue(is_path_allowed("POST", "/api/generate"))
        self.assertTrue(is_path_allowed("POST", "/api/chat"))
        self.assertTrue(is_path_allowed("POST", "/api/embeddings"))

    def test_blocked_dangerous_endpoints(self):
        # Administrative endpoints must be rejected
        self.assertFalse(is_path_allowed("POST", "/api/pull"))
        self.assertFalse(is_path_allowed("POST", "/api/delete"))
        self.assertFalse(is_path_allowed("POST", "/api/create"))
        self.assertFalse(is_path_allowed("POST", "/api/push"))
        self.assertFalse(is_path_allowed("POST", "/api/copy"))
        self.assertFalse(is_path_allowed("GET", "/etc/passwd"))

    def test_token_authentication(self):
        expected_token = "secret-token-abcdef123456"

        # Correct Bearer token
        self.assertTrue(check_auth({"authorization": f"Bearer {expected_token}"}, expected_token))
        # Correct custom header
        self.assertTrue(check_auth({"x-ollama-proxy-token": expected_token}, expected_token))

        # Missing token
        self.assertFalse(check_auth({}, expected_token))
        # Wrong token
        self.assertFalse(check_auth({"authorization": "Bearer wrong-token"}, expected_token))
        self.assertFalse(check_auth({"x-ollama-proxy-token": "wrong-token"}, expected_token))


class TestOllamaInference(unittest.IsolatedAsyncioTestCase):
    """Test calling Ollama inference with mocked responses."""

    @patch("httpx.AsyncClient.post")
    async def test_call_llm_ollama_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"response": "Sanitize inputs with parameterized queries."}
        mock_post.return_value = mock_resp

        env = {
            "AI_PROVIDER": "ollama",
            "OLLAMA_URL": "http://127.0.0.1:11434",
            "OLLAMA_MODEL": "qwen2.5-coder:7b",
        }
        with patch.dict(os.environ, env, clear=True):
            answer, model_used = await call_llm("How to fix SQLi?", task="chat")
            self.assertIn("Sanitize inputs", answer)
            self.assertEqual(model_used, "Ollama (qwen2.5-coder:7b)")

    @patch("httpx.AsyncClient.post")
    async def test_no_gemini_fallback_when_ai_provider_is_ollama(self, mock_post):
        """When AI_PROVIDER=ollama, failure should not fall back to Gemini even if key exists."""
        mock_post.side_effect = httpx.ConnectError("Connection refused to Ollama")

        env = {
            "AI_PROVIDER": "ollama",
            "OLLAMA_URL": "http://127.0.0.1:11434",
            "OLLAMA_MODEL": "qwen2.5-coder:7b",
            "GEMINI_API_KEY": "AIzaSyTestFakeGeminiKeyShouldNotBeUsed",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("models.llm_chain._call_gemini", new_callable=AsyncMock) as mock_gemini:
                with self.assertRaises(LLMProviderError):
                    await call_llm("Question", task="chat")
                # Ensure Gemini was never contacted
                mock_gemini.assert_not_called()

    @patch("httpx.AsyncClient.post")
    async def test_ollama_timeout_error(self, mock_post):
        """Verify timeout raises LLMTimeoutError with descriptive message."""
        mock_post.side_effect = httpx.ReadTimeout("Read timed out")

        env = {
            "AI_PROVIDER": "ollama",
            "OLLAMA_URL": "http://127.0.0.1:11434",
            "OLLAMA_MODEL": "qwen2.5-coder:7b",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(LLMTimeoutError) as ctx:
                await call_llm("Question", task="chat")
            self.assertIn("timed out", str(ctx.exception).lower())

    async def test_stream_ollama(self):
        """Verify streaming chunks are yielded correctly."""
        class MockStreamResponse:
            status_code = 200
            headers = {"content-type": "application/json"}

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

            async def aiter_lines(self):
                lines = [
                    json.dumps({"response": "Hello "}),
                    json.dumps({"response": "from "}),
                    json.dumps({"response": "Ollama!", "done": True}),
                ]
                for line in lines:
                    yield line

        with patch("httpx.AsyncClient.stream", return_value=MockStreamResponse()):
            env = {
                "OLLAMA_URL": "http://127.0.0.1:11434",
                "OLLAMA_MODEL": "qwen2.5-coder:7b",
            }
            with patch.dict(os.environ, env, clear=True):
                tokens = []
                async for chunk in stream_ollama("Hello"):
                    tokens.append(chunk)

                self.assertEqual("".join(tokens), "Hello from Ollama!")


class TestChatEndpoints(unittest.TestCase):
    """Test FastAPI /api/chat and /api/chat/stream endpoints."""

    @patch("main.call_llm", new_callable=AsyncMock)
    def test_chat_non_streaming(self, mock_call_llm):
        mock_call_llm.return_value = ("Use CSRF tokens for form submissions.", "Ollama (qwen2.5-coder:7b)")

        res = client.post("/api/chat", json={
            "message": "How to prevent CSRF?",
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("CSRF tokens", data.get("response", ""))
        self.assertEqual(data.get("model"), "Ollama (qwen2.5-coder:7b)")

    @patch("main.stream_ollama")
    def test_chat_streaming_sse(self, mock_stream):
        async def fake_stream(prompt, task="chat"):
            yield "Token 1"
            yield "Token 2"

        mock_stream.side_effect = fake_stream

        res = client.post("/api/chat", json={
            "message": "Explain XSS",
            "stream": True,
        })
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/event-stream", res.headers.get("content-type", ""))
        content = res.text
        self.assertIn("Token 1", content)
        self.assertIn("Token 2", content)
        self.assertIn("[DONE]", content)


if __name__ == "__main__":
    unittest.main()
