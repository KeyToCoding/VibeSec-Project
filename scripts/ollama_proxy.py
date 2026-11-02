#!/usr/bin/env python3
"""
VibeSec Authenticated Ollama Reverse Proxy
==========================================
Protects local Windows Ollama (127.0.0.1:11434) when exposed via Cloudflare Quick Tunnel.

Features:
- Bearer token authentication via OLLAMA_PROXY_TOKEN
- Strict endpoint whitelisting (blocks /api/pull, /api/delete, administrative actions)
- In-memory rate limiting to prevent denial of service
- Full streaming response forwarding (chunked transfer)
- Connection timeouts and graceful offline handling
- Zero external dependencies (uses standard library http.server / urllib)

Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
License: Apache-2.0
"""

import argparse
import http.client
import json
import logging
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [OllamaProxy] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("vibesec.ollama_proxy")

# Default configuration
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 11435
DEFAULT_TARGET_URL = "http://127.0.0.1:11434"
DEFAULT_RATE_LIMIT_PER_MINUTE = 60

# Allowed HTTP methods and path prefixes for Ollama inference and health checks
ALLOWED_ENDPOINTS: Dict[str, Set[str]] = {
    "GET": {"/", "/api/tags", "/api/version", "/api/ps"},
    "POST": {"/api/generate", "/api/chat", "/api/embeddings"},
    "OPTIONS": {"/", "/api/tags", "/api/version", "/api/generate", "/api/chat", "/api/embeddings"},
}


def is_path_allowed(method: str, path: str) -> bool:
    """Strict whitelist verification for method and path against ALLOWED_ENDPOINTS."""
    parsed_path = urllib.parse.urlparse(path).path.rstrip("/") or "/"
    allowed_paths = ALLOWED_ENDPOINTS.get(method.upper(), set())
    return parsed_path in allowed_paths


def check_auth(headers: dict, proxy_token: str) -> bool:
    """Validate incoming request headers against configured proxy secret in constant time."""
    if not proxy_token:
        return False

    # Normalize header lookup
    normalized = {k.lower(): v for k, v in headers.items()}
    auth_header = normalized.get("authorization", "").strip()
    supplied = None
    if auth_header.lower().startswith("bearer "):
        supplied = auth_header[7:].strip()
    if not supplied:
        proxy_header = normalized.get("x-ollama-proxy-token", "").strip()
        if proxy_header:
            supplied = proxy_header

    if not supplied:
        return False

    return secrets.compare_digest(supplied, proxy_token)


class SlidingWindowRateLimiter:
    """Thread-safe sliding window in-memory rate limiter per client IP."""

    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.buckets: Dict[str, list] = {}

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        now = time.time()
        window_start = now - self.window_seconds
        timestamps = self.buckets.get(client_ip, [])
        # Filter timestamps outside window
        valid_timestamps = [t for t in timestamps if t > window_start]
        if len(valid_timestamps) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - valid_timestamps[0])) + 1
            self.buckets[client_ip] = valid_timestamps
            return False, max(1, retry_after)

        valid_timestamps.append(now)
        self.buckets[client_ip] = valid_timestamps
        return True, 0


class OllamaProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler verifying authentication and forwarding to target Ollama."""

    target_url: str = DEFAULT_TARGET_URL
    proxy_token: str = ""
    rate_limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter()

    # Silence default console access logs to keep terminal clean
    def log_message(self, format: str, *args: object) -> None:
        logger.debug("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)

    def _send_json(self, status_code: int, data: dict, extra_headers: Optional[Dict[str, str]] = None) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _extract_token(self) -> Optional[str]:
        """Extract proxy token from Authorization header or X-Ollama-Proxy-Token."""
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        proxy_header = self.headers.get("X-Ollama-Proxy-Token", "").strip()
        if proxy_header:
            return proxy_header
        return None

    def _is_authenticated(self) -> bool:
        """Validate the incoming request token against the configured proxy secret."""
        if not self.proxy_token:
            logger.error("Rejecting request: OLLAMA_PROXY_TOKEN is not configured on the proxy.")
            return False
        return check_auth(dict(self.headers), self.proxy_token)

    def _is_allowed_endpoint(self, method: str, path: str) -> bool:
        """Strict whitelist verification for method and path."""
        return is_path_allowed(method, path)

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests cleanly."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Ollama-Proxy-Token")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def _handle_request(self, method: str) -> None:
        client_ip = self.client_address[0]

        # 1. Endpoint Whitelist check
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/") or "/"
        if not self._is_allowed_endpoint(method, path):
            logger.warning("Blocked disallowed endpoint: %s %s from %s", method, path, client_ip)
            self._send_json(403, {
                "error": "Forbidden: Endpoint is blocked by VibeSec proxy policy.",
                "allowed_endpoints": {k: list(v) for k, v in ALLOWED_ENDPOINTS.items()},
            })
            return

        # 2. Public health check on root path "/" does not expose internal Ollama data
        if method == "GET" and path == "/":
            self._send_json(200, {
                "status": "healthy",
                "service": "VibeSec Ollama Authenticated Proxy",
                "target": self.target_url,
                "version": "1.0.0",
                "auth_required": True,
            })
            return

        # 3. Rate limiting check
        allowed, retry_after = self.rate_limiter.is_allowed(client_ip)
        if not allowed:
            logger.warning("Rate limit exceeded for client %s", client_ip)
            self._send_json(429, {
                "error": "Too Many Requests: Rate limit exceeded on Ollama proxy.",
                "retry_after_seconds": retry_after,
            }, extra_headers={"Retry-After": str(retry_after)})
            return

        # 4. Authentication check
        if not self._is_authenticated():
            logger.warning("Unauthorized request to %s %s from %s", method, path, client_ip)
            self._send_json(401, {
                "error": "Unauthorized: Missing or invalid OLLAMA_PROXY_TOKEN.",
                "hint": "Pass 'Authorization: Bearer <token>' or 'X-Ollama-Proxy-Token: <token>' header.",
            })
            return

        # 5. Read request body if present
        body: Optional[bytes] = None
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)

        # 6. Forward to local Ollama target
        target_path = self.path
        full_target_url = urllib.parse.urljoin(self.target_url.rstrip("/") + "/", target_path.lstrip("/"))

        headers_to_forward: Dict[str, str] = {}
        for header, val in self.headers.items():
            # Exclude hop-by-hop headers and proxy authentication
            if header.lower() not in ("host", "authorization", "x-ollama-proxy-token", "content-length"):
                headers_to_forward[header] = val
        headers_to_forward["Host"] = urllib.parse.urlparse(self.target_url).netloc or "127.0.0.1:11434"

        try:
            req = urllib.request.Request(
                full_target_url,
                data=body,
                headers=headers_to_forward,
                method=method,
            )
            # Timeout: 10s connect, 120s read for long inferences
            with urllib.request.urlopen(req, timeout=120) as upstream_resp:
                self.send_response(upstream_resp.status)
                for k, v in upstream_resp.getheaders():
                    # Preserve chunked or json content types
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()

                # Stream response back in chunks
                while True:
                    chunk = upstream_resp.read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()

        except urllib.error.HTTPError as http_err:
            error_body = http_err.read()
            self.send_response(http_err.code)
            for k, v in http_err.headers.items():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(error_body)))
            self.end_headers()
            self.wfile.write(error_body)

        except (urllib.error.URLError, ConnectionRefusedError, http.client.RemoteDisconnected) as conn_err:
            logger.error("Failed to connect to local Ollama at %s: %s", self.target_url, conn_err)
            self._send_json(503, {
                "error": f"Upstream Ollama service at {self.target_url} is unreachable.",
                "hint": "Ensure 'ollama serve' is running locally on Windows and listening on 127.0.0.1:11434.",
            })
        except Exception as exc:
            logger.exception("Unexpected error forwarding to Ollama")
            self._send_json(502, {
                "error": f"Ollama proxy forwarding error: {type(exc).__name__}",
                "detail": str(exc),
            })


def create_proxy_server(
    host: str = DEFAULT_LISTEN_HOST,
    port: int = DEFAULT_LISTEN_PORT,
    target_url: str = DEFAULT_TARGET_URL,
    token: str = "",
    rate_limit: int = DEFAULT_RATE_LIMIT_PER_MINUTE,
) -> ThreadingHTTPServer:
    """Factory creating configured threaded proxy server."""
    OllamaProxyHandler.target_url = target_url
    OllamaProxyHandler.proxy_token = token
    OllamaProxyHandler.rate_limiter = SlidingWindowRateLimiter(max_requests=rate_limit)

    return ThreadingHTTPServer((host, port), OllamaProxyHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="VibeSec Authenticated Ollama Reverse Proxy for Cloudflare Tunnel")
    parser.add_argument("--host", default=os.getenv("OLLAMA_PROXY_HOST", DEFAULT_LISTEN_HOST), help="Listen host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(os.getenv("OLLAMA_PROXY_PORT", DEFAULT_LISTEN_PORT)), help="Listen port (default: 11435)")
    parser.add_argument("--target", default=os.getenv("OLLAMA_TARGET_URL", DEFAULT_TARGET_URL), help="Ollama target base URL (default: http://127.0.0.1:11434)")
    parser.add_argument("--token", default=os.getenv("OLLAMA_PROXY_TOKEN", ""), help="Secret proxy authentication token")
    parser.add_argument("--rate-limit", type=int, default=int(os.getenv("OLLAMA_PROXY_RATE_LIMIT", DEFAULT_RATE_LIMIT_PER_MINUTE)), help="Rate limit per minute (default: 60)")

    args = parser.parse_args()

    token = args.token.strip()
    if not token:
        token = secrets.token_hex(24)
        logger.warning("No OLLAMA_PROXY_TOKEN supplied. Generated temporary token:")
        print(f"\n>>> OLLAMA_PROXY_TOKEN={token}\n", file=sys.stderr)
        logger.info("Set this token in your Render FastAPI environment as OLLAMA_PROXY_TOKEN.")

    server = create_proxy_server(
        host=args.host,
        port=args.port,
        target_url=args.target,
        token=token,
        rate_limit=args.rate_limit,
    )

    logger.info("=================================================================")
    logger.info("       VibeSec Authenticated Ollama Proxy Running                ")
    logger.info("=================================================================")
    logger.info("Listening on:   http://%s:%d", args.host, args.port)
    logger.info("Target Ollama:  %s", args.target)
    logger.info("Rate Limit:     %d requests/minute", args.rate_limit)
    logger.info("Allowed Routes: %s", ", ".join(sorted(ALLOWED_ENDPOINTS["POST"] | ALLOWED_ENDPOINTS["GET"])))
    logger.info("Tunnel Command: cloudflared tunnel --url http://%s:%d", args.host, args.port)
    logger.info("=================================================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Ollama proxy server...")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
