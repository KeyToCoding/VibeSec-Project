"""
VibeSec Website URL Security Scanner
Fetches live websites, analyzes HTTP response headers, inspects cookies,
discovers script tags, downloads remote JS bundles, and scans them for exposed secrets
and frontend vulnerabilities.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import re
import time
import socket
import ipaddress
import httpx
import logging
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin, urlparse
from .code_scanner import scan_code, compute_severity_counts
from .env_detector import is_aws_example_credential, is_placeholder_value

logger = logging.getLogger("vibesec.url_scanner")


def is_safe_public_url(url: str) -> Tuple[bool, str, str]:
    """Validate that the target URL is a safe public address and not an internal/metadata IP (SSRF protection)."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Malformed URL string: {exc}", url

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS protocols are allowed.", url

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "Target URL missing hostname.", url

    if (
        hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal")
        or hostname.endswith((".internal", ".local"))
    ):
        return False, "SSRF Protection: Requests to private, local loopback, or cloud metadata endpoints are forbidden.", url

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False, f"SSRF Protection: Hostname resolves to restricted private IP address ({ip_str}).", url
    except Exception as exc:
        return False, f"DNS resolution failed for target host ({hostname}): {exc}", url

    return True, "", url

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "description": "The server does not enforce encrypted HTTPS communication via Strict-Transport-Security header.",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to server responses."
    },
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy (CSP)",
        "severity": "high",
        "description": "No Content-Security-Policy header defined. The site is vulnerable to Cross-Site Scripting (XSS) and data injection.",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix": "Configure a restrictive Content-Security-Policy header specifying trusted script and style sources."
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options (Clickjacking Risk)",
        "severity": "medium",
        "description": "Without X-Frame-Options or CSP frame-ancestors, the site can be embedded inside unauthorized iframes.",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options",
        "severity": "low",
        "description": "MIME-sniffing protection disabled. Browsers may interpret non-executable MIME types as executable.",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix": "Set 'X-Content-Type-Options: nosniff'."
    },
    "Referrer-Policy": {
        "title": "Missing Referrer-Policy",
        "severity": "low",
        "description": "Referrer headers may leak sensitive URLs and query parameters to third-party endpoints.",
        "owasp": "A01:2021-Broken Access Control",
        "fix": "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
    }
}

SECRET_REGEXES = [
    (r"(sk-[a-zA-Z0-9]{20,})", "OpenAI / Stripe Secret Key"),
    (r"(AIza[0-9A-Za-z-_]{35})", "Google Cloud API Key"),
    (r"(ghp_[a-zA-Z0-9]{36})", "GitHub Personal Access Token"),
    (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID"),
    (r"(sq0atp-[0-9A-Za-z\-_]{22})", "Square Access Token"),
    (r"(eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]+)", "Exposed JWT Token")
]


def check_secrets_in_text(text: str, source_url: str) -> List[Dict[str, Any]]:
    """Scan text or JS file for exposed credentials and API keys."""
    findings = []
    lines = text.splitlines()
    for regex_pat, key_type in SECRET_REGEXES:
        pattern = re.compile(regex_pat)
        for idx, line in enumerate(lines, start=1):
            match = pattern.search(line)
            if match:
                token = match.group(1)
                if is_placeholder_value(token) or is_aws_example_credential(token):
                    continue
                masked_token = token[:4] + "*" * (len(token) - 8) + token[-4:] if len(token) > 10 else "***"
                findings.append({
                    "title": f"Exposed Credential: {key_type}",
                    "severity": "critical",
                    "owasp": "A07:2021-Identification and Authentication Failures",
                    "description": f"A hardcoded secret key ({key_type}) was detected in public client asset ({masked_token}).",
                    "attack_scenario": "Attackers scraping client-side bundles can extract this token and access protected APIs.",
                    "line_hint": idx,
                    "file": source_url,
                    "confidence": "high",
                    "fix": "Revoke the exposed key immediately and store credentials in secure server-side environment variables."
                })
    return findings


async def scan_url(url: str) -> Dict[str, Any]:
    """
    Scan a live URL:
      - Validates headers & cookies
      - Extracts and downloads JS bundles
      - Analyzes JS for secrets and vulnerabilities
    """
    start_time = time.time()
    is_safe, error_msg, normalized_url = is_safe_public_url(url)
    if not is_safe:
        raise ValueError(error_msg)
    url = normalized_url

    all_vulnerabilities: List[Dict[str, Any]] = []
    header_status: Dict[str, Any] = {"present": {}, "missing": {}}
    cookies_inspected: List[Dict[str, Any]] = []
    js_files_found: List[str] = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, headers={"User-Agent": "Mozilla/5.0 VibeSec-Auditor/1.0"}) as client:
        try:
            resp = await client.get(url)
            final_url = str(resp.url)
            response_headers = dict(resp.headers)

            # Inspect Headers
            for header_name, meta in RECOMMENDED_HEADERS.items():
                # Case-insensitive search
                found_val = None
                for h_k, h_v in response_headers.items():
                    if h_k.lower() == header_name.lower():
                        found_val = h_v
                        break

                if found_val:
                    header_status["present"][header_name] = found_val
                else:
                    header_status["missing"][header_name] = meta["description"]
                    all_vulnerabilities.append({
                        "title": meta["title"],
                        "severity": meta["severity"],
                        "owasp": meta["owasp"],
                        "description": meta["description"],
                        "attack_scenario": "Absence of this security header leaves web users susceptible to man-in-the-middle or cross-origin exploits.",
                        "file": final_url,
                        "line_hint": 0,
                        "confidence": "high",
                        "fix": meta["fix"]
                    })

            # Inspect Cookies
            for name, value in resp.cookies.items():
                cookies_inspected.append({"name": name, "value_len": len(value)})

            # Extract script tags from HTML
            html_text = resp.text
            # Check secrets directly in HTML
            html_secrets = check_secrets_in_text(html_text, final_url)
            all_vulnerabilities.extend(html_secrets)

            script_srcs = re.findall(r'''<script[^>]+src=["']([^"']+)["']''', html_text, re.IGNORECASE)
            for src in script_srcs:
                full_js_url = urljoin(final_url, src)
                if full_js_url not in js_files_found:
                    js_files_found.append(full_js_url)

            # Download and scan up to top 5 JS bundles to prevent timeout (with SSRF check on each asset)
            for js_url in js_files_found[:5]:
                safe_js, _, _ = is_safe_public_url(js_url)
                if not safe_js:
                    continue
                try:
                    js_resp = await client.get(js_url, timeout=8.0)
                    if js_resp.status_code == 200:
                        js_content = js_resp.text
                        # Check secrets
                        sec_findings = check_secrets_in_text(js_content, js_url)
                        all_vulnerabilities.extend(sec_findings)

                        # Code scan on JS (skip giant minified files over 250KB for deep AST)
                        if len(js_content) < 250000:
                            code_rep = await scan_code(js_content[:40000], language="javascript", filename=js_url.split("/")[-1])
                            all_vulnerabilities.extend(code_rep.get("vulnerabilities", []))
                except Exception as e_js:
                    logger.warning(f"Could not scan script {js_url}: {e_js}")

        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            all_vulnerabilities.append({
                "title": "URL Unreachable or Request Timeout",
                "severity": "high",
                "owasp": "A05:2021-Security Misconfiguration",
                "description": f"Failed to connect to target URL: {str(e)}",
                "attack_scenario": "Service is unavailable or blocking automated audit probes.",
                "file": url,
                "line_hint": 0,
                "confidence": "high",
                "fix": "Verify that the target URL is active, supports HTTPS, and permits inbound traffic."
            })

    scan_time = round(time.time() - start_time, 2)
    severity_counts = compute_severity_counts(all_vulnerabilities)

    return {
        "target_url": url,
        "input_type": "url",
        "language": "html/javascript",
        "header_status": header_status,
        "cookies_inspected": cookies_inspected,
        "js_files_scanned": js_files_found[:5],
        "vulnerabilities": all_vulnerabilities,
        "hallucinated_packages": [],
        "severity_counts": severity_counts,
        "files_scanned": 1 + len(js_files_found[:5]),
        "files_skipped": js_files_found[5:],
        "summary": f"Scanned URL {url}. Discovered {len(js_files_found)} JS scripts. Found {len(all_vulnerabilities)} vulnerabilities in {scan_time}s.",
        "scan_time_seconds": scan_time
    }
