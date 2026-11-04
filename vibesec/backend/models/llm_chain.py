"""VibeSec LLM Chain Engine.

Primary provider: Ollama (local or remote Colab/ngrok).
Optional fallbacks: Groq, then Gemini.

Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional, Tuple

import httpx
from dotenv import load_dotenv

logger = logging.getLogger("vibesec.llm")


class LLMProviderError(RuntimeError):
    """Raised when no configured provider can produce a usable response."""


class LLMTimeoutError(LLMProviderError):
    """Raised when an upstream inference request times out."""


VULN_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerable": {"type": "boolean"},
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "owasp": {"type": "string"},
        "description": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "line_hint": {"type": "integer"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "fix": {"type": "string"},
    },
    "required": [
        "is_vulnerable", "title", "severity", "owasp", "description",
        "attack_scenario", "line_hint", "confidence", "fix",
    ],
    "additionalProperties": False,
}

# Resolve .env relative to this file, not the process working directory.
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=False)


def _normalize_ollama_base_url(value: Optional[str]) -> str:
    """Return a base URL, removing accidental Ollama API endpoint suffixes."""
    url = (value or "").strip().rstrip("/")
    suffixes = ("/api/generate", "/api/tags", "/api/chat", "/api")

    # Loop so malformed values such as /api/generate/api are cleaned safely.
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if url.lower().endswith(suffix):
                url = url[: -len(suffix)].rstrip("/")
                changed = True
                break

    return url


def get_ollama_config() -> Tuple[str, str]:
    """Read the canonical Ollama base URL and model at call time."""
    # Environment variables explicitly supplied by the process take precedence;
    # otherwise values loaded from the backend .env file are used.
    # Default to local 127.0.0.1:11434 for zero-config development.
    raw_url = os.getenv("OLLAMA_URL") or os.getenv("OLLAMA_PROXY_URL") or os.getenv("OLLAMA_BASE_URL") or os.getenv("COLAB_NGROK_URL") or "http://127.0.0.1:11434"
    base_url = _normalize_ollama_base_url(raw_url)
    model = (os.getenv("OLLAMA_MODEL") or "qwen2.5-coder:7b").strip()
    return base_url, model


def get_ollama_headers() -> dict:
    """Return headers for Ollama requests, injecting OLLAMA_PROXY_TOKEN if configured."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VibeSec/1.0",
        "ngrok-skip-browser-warning": "true",
    }
    proxy_token = (os.getenv("OLLAMA_PROXY_TOKEN") or "").strip()
    if proxy_token:
        headers["Authorization"] = f"Bearer {proxy_token}"
        headers["X-Ollama-Proxy-Token"] = proxy_token
    return headers


# Backwards-compatible module-level values used by main.py and older imports.
OLLAMA_URL, OLLAMA_MODEL = get_ollama_config()
COLAB_NGROK_URL = _normalize_ollama_base_url(os.getenv("COLAB_NGROK_URL", ""))
GROQ_API_KEY = (os.getenv("GROQ_API_KEY") or "").strip()
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
GEMINI_MODEL = (os.getenv("GEMINI_MODEL") or "gemini-1.5-flash").strip()

NGROK_HEADERS = get_ollama_headers()
# Dynamic property-like access for OLLAMA_HEADERS
OLLAMA_HEADERS = NGROK_HEADERS


def _short_error(value: object, limit: int = 300) -> str:
    """Return a one-line diagnostic preview suitable for logs and HTTP errors."""
    text = " ".join(str(value or "").split())
    return text[:limit] or "No additional error details provided"


def _response_error_detail(response: httpx.Response) -> str:
    """Extract a useful error message without assuming the body is JSON."""
    try:
        body = response.json()
    except ValueError:
        body = None

    if isinstance(body, dict):
        detail = body.get("error") or body.get("detail") or body.get("message")
        if detail:
            return _short_error(detail)

    return _short_error(response.text)


def _close_unclosed_code_blocks(text: str) -> str:
    """Ensure any opened code fences (```) are cleanly closed to prevent broken rendering."""
    if not isinstance(text, str):
        return ""
    count = text.count("```")
    if count % 2 != 0:
        return text.rstrip() + "\n```\n"
    return text


def _stitch_continuation(original: str, continuation: str) -> str:
    """Intelligently combine truncated text with its continuation, eliminating overlapping sentences."""
    orig = original.rstrip()
    cont = continuation.strip()
    if not cont:
        return _close_unclosed_code_blocks(orig)

    # Remove conversational filler at start of continuation if any (e.g., "Sure, continuing:")
    cont = re.sub(r"^(?:sure|continuing|here is the continuation|to continue)[:,\-]?\s*", "", cont, flags=re.I)

    # Check for overlapping prefix/suffix
    max_check = min(len(orig), len(cont), 250)
    overlap_len = 0
    for length in range(max_check, 8, -1):
        if orig.endswith(cont[:length]):
            overlap_len = length
            break

    if overlap_len > 0:
        stitched = orig + cont[overlap_len:]
    else:
        # Check if continuation starts with a bullet point or sentence
        if cont.startswith(("-", "*", "•", "1.", "2.", "3.", "4.", "5.")):
            stitched = orig + "\n" + cont
        elif orig and orig[-1] not in (" ", "\n", ".", "!", "?", ":", ";", "`"):
            stitched = orig + " " + cont
        elif orig and orig[-1] in (".", "!", "?"):
            stitched = orig + "\n" + cont
        else:
            stitched = orig + " " + cont

    return _close_unclosed_code_blocks(stitched)


async def _call_ollama(
    prompt: str,
    base_url: str,
    model: str,
    task: str,
) -> Optional[str]:
    """Call Ollama's native generate API and preserve actionable failures."""
    base_url = _normalize_ollama_base_url(base_url)
    if not base_url:
        raise RuntimeError("OLLAMA_URL is not configured.")
    if not model:
        raise RuntimeError("OLLAMA_MODEL is empty.")

    endpoint = f"{base_url}/api/generate"
    token_limits = {
        # Concise interactive answers are faster on CPU-hosted local inference.
        "chat": 384,
        # Leave enough room for the complete required JSON object.
        "chunk_analysis": 220,
        "patch_generation": 220,
    }
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "10m",
        "options": {
            "temperature": 0.1 if task == "chunk_analysis" else 0.2,
            "num_predict": token_limits.get(task, 160),
        },
    }

    # Constrain vulnerability analysis to the exact schema expected by vuln_agent.
    if task == "chunk_analysis":
        payload["format"] = VULN_ANALYSIS_SCHEMA
    elif task != "chat":
        payload["format"] = "json"

    # Leave margin for CPU inference while outer FastAPI/Express deadlines remain longer.
    read_timeout = 130.0 if task == "chat" else 85.0
    timeout = httpx.Timeout(
        connect=12.0,
        read=read_timeout,
        write=12.0,
        pool=8.0,
    )
    start_time = time.perf_counter()
    headers = get_ollama_headers()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            response = await client.post(
                endpoint,
                json=payload,
                headers=headers,
            )
    except httpx.TimeoutException as exc:
        elapsed = time.perf_counter() - start_time
        logger.warning(
            "Ollama timeout: model=%s elapsed=%.2fs error=%s",
            model,
            elapsed,
            type(exc).__name__,
        )
        if base_url.lower().startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
            recovery_hint = (
                "Check that the local Ollama service is running. Chat output is capped "
                "to keep responses concise on CPU-only systems."
            )
        else:
            recovery_hint = "Check that the configured remote Ollama endpoint and tunnel are reachable."
        raise LLMTimeoutError(
            f"Ollama request timed out after {elapsed:.1f}s ({type(exc).__name__}). "
            f"{recovery_hint}"
        ) from exc
    except httpx.RequestError as exc:
        elapsed = time.perf_counter() - start_time
        logger.warning(
            "Ollama connection error: model=%s elapsed=%.2fs error=%s detail=%s",
            model,
            elapsed,
            type(exc).__name__,
            _short_error(exc),
        )
        raise RuntimeError(
            f"Could not connect to Ollama ({type(exc).__name__}): {_short_error(exc)}"
        ) from exc

    elapsed = time.perf_counter() - start_time
    content_type = response.headers.get("content-type", "unknown").lower()

    if response.status_code != 200:
        detail = _response_error_detail(response)
        logger.warning(
            "Ollama HTTP failure: status=%d model=%s elapsed=%.2fs content_type=%s body=%s",
            response.status_code,
            model,
            elapsed,
            content_type,
            detail,
        )
        raise RuntimeError(
            f"Ollama returned HTTP {response.status_code} for /api/generate: {detail}"
        )

    if "json" not in content_type:
        detail = _short_error(response.text)
        logger.warning(
            "Ollama returned non-JSON: status=%d elapsed=%.2fs content_type=%s body=%s",
            response.status_code,
            elapsed,
            content_type,
            detail,
        )
        raise RuntimeError(
            "Ollama /api/generate returned HTTP 200 but did not return JSON "
            f"(content-type={content_type}). Response: {detail}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        detail = _short_error(response.text)
        logger.warning("Ollama returned invalid JSON: %s", detail)
        raise RuntimeError(f"Ollama returned invalid JSON: {detail}") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Ollama returned JSON in an unexpected format.")

    if data.get("error"):
        detail = _short_error(data["error"])
        logger.warning("Ollama model error: %s", detail)
        raise RuntimeError(f"Ollama model error: {detail}")

    logger.info(
        "Ollama completion metadata: task=%s done_reason=%s eval_count=%s prompt_eval_count=%s",
        task,
        data.get("done_reason"),
        data.get("eval_count"),
        data.get("prompt_eval_count"),
    )

    done_reason = data.get("done_reason")
    result = data.get("response")
    if not isinstance(result, str) or not result.strip():
        logger.warning(
            "Ollama returned an empty response: model=%s elapsed=%.2fs",
            model,
            elapsed,
        )
        raise RuntimeError("Ollama returned an empty response.")

    # Bounded recovery if chat generation stopped due to token limit
    if task == "chat" and done_reason == "length":
        logger.warning(
            "Ollama chat output reached token limit (done_reason=length, eval_count=%s); initiating bounded continuation.",
            data.get("eval_count"),
        )
        try:
            cont_prompt = (
                f"{prompt}\n{result.strip()}\n\n"
                "[System: The previous response reached the token limit. "
                "Conclude the explanation concisely in 1 to 2 bullet points. "
                "Do NOT repeat any existing sentences or bullet points. "
                "Close all open code blocks and end with a complete sentence.]\n"
                "Assistant (continued):"
            )
            cont_payload = {
                "model": model,
                "prompt": cont_prompt,
                "stream": False,
                "keep_alive": "10m",
                "options": {
                    "temperature": 0.2,
                    "num_predict": 160,
                },
            }
            cont_timeout = httpx.Timeout(connect=8.0, read=35.0, write=8.0, pool=8.0)
            async with httpx.AsyncClient(timeout=cont_timeout, follow_redirects=False) as cont_client:
                cont_resp = await cont_client.post(endpoint, json=cont_payload, headers=headers)
                if cont_resp.status_code == 200:
                    cont_data = cont_resp.json()
                    cont_text = cont_data.get("response", "")
                    if isinstance(cont_text, str) and cont_text.strip():
                        result = _stitch_continuation(result, cont_text)
                        logger.info(
                            "Ollama bounded continuation succeeded: extra_eval=%s total_chars=%d",
                            cont_data.get("eval_count"),
                            len(result),
                        )
        except Exception as cont_err:
            logger.warning("Ollama continuation request failed: %s; ensuring code blocks are closed.", _short_error(cont_err))

    final_result = _close_unclosed_code_blocks(result.strip())
    logger.info(
        "Ollama inference succeeded: model=%s elapsed=%.2fs response_chars=%d",
        model,
        elapsed,
        len(final_result),
    )
    return final_result


async def stream_ollama(
    prompt: str,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    task: str = "chat",
):
    """Stream token chunks from Ollama generate API."""
    resolved_base_url, resolved_model = get_ollama_config()
    target_url = _normalize_ollama_base_url(base_url or resolved_base_url)
    target_model = (model or resolved_model).strip()

    if not target_url:
        raise LLMProviderError("OLLAMA_URL is not configured.")
    if not target_model:
        raise LLMProviderError("OLLAMA_MODEL is empty.")

    endpoint = f"{target_url}/api/generate"
    payload = {
        "model": target_model,
        "prompt": prompt,
        "stream": True,
        "keep_alive": "10m",
        "options": {
            "temperature": 0.2,
            "num_predict": 384 if task == "chat" else 256 if task == "patch_generation" else 512,
        },
    }
    timeout = httpx.Timeout(connect=12.0, read=130.0, write=12.0, pool=8.0)
    headers = get_ollama_headers()

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream("POST", endpoint, json=payload, headers=headers) as response:
                if response.status_code != 200:
                    detail = _response_error_detail(response)
                    raise LLMProviderError(f"Ollama returned HTTP {response.status_code}: {detail}")
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk_obj = json.loads(line)
                        token = chunk_obj.get("response", "")
                        if token:
                            yield token
                        if chunk_obj.get("done", False):
                            break
                    except json.JSONDecodeError:
                        continue
    except httpx.TimeoutException as exc:
        raise LLMTimeoutError(f"Ollama stream timed out: {type(exc).__name__}") from exc
    except httpx.RequestError as exc:
        raise LLMProviderError(f"Could not connect to Ollama ({type(exc).__name__}): {_short_error(exc)}") from exc


async def _call_groq(prompt: str, api_key: str, task: str) -> Optional[str]:
    """Optional fallback: call Groq using the SDK already used by this project."""
    try:
        from groq import AsyncGroq

        client = AsyncGroq(api_key=api_key, timeout=20.0, max_retries=0)
        completion = await client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are VibeSec, an application-security assistant. "
                        "Give accurate, practical, safe answers."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            model="llama-3.1-70b-versatile",
            temperature=0.1,
            **({"response_format": {"type": "json_object"}} if task != "chat" else {}),
        )
        text = completion.choices[0].message.content
        if text and text.strip():
            return text.strip()
    except Exception as exc:
        logger.warning(
            "Groq primary model failed (%s): %s; trying fallback model",
            type(exc).__name__,
            _short_error(exc),
        )

    try:
        from groq import AsyncGroq

        client = AsyncGroq(api_key=api_key, timeout=20.0, max_retries=0)
        completion = await client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            temperature=0.1,
        )
        text = completion.choices[0].message.content
        return text.strip() if text and text.strip() else None
    except Exception as exc:
        logger.warning(
            "Groq fallback failed (%s): %s",
            type(exc).__name__,
            _short_error(exc),
        )
        return None


async def _call_gemini(prompt: str, api_key: str, model_name: Optional[str] = None) -> Optional[str]:
    """Gemini caller supporting GEMINI_MODEL."""
    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        target_model = (model_name or os.getenv("GEMINI_MODEL") or "gemini-1.5-flash").strip()
        model = genai.GenerativeModel(target_model)
        response = await model.generate_content_async(prompt)
        text = getattr(response, "text", None) if response else None
        return text.strip() if isinstance(text, str) and text.strip() else None
    except Exception as exc:
        logger.warning(
            "Gemini provider failed (%s): %s",
            type(exc).__name__,
            _short_error(exc),
        )
        return None


async def call_llm(prompt: str, task: str = "analysis") -> Tuple[str, str]:
    """Call AI provider according to environment configuration.

    In zero-cost deployment (AI_PROVIDER=ollama, default):
      Uses Ollama exclusively (local or remote tunnel) with qwen2.5-coder:7b.
      Automatic Gemini fallback is disabled.
    When AI_PROVIDER=gemini:
      Uses Gemini API first if configured.

    Returns (response_text, model_identifier).
    """
    base_url, model = get_ollama_config()
    errors = []
    ollama_timed_out = False

    gemini_key = (os.getenv("GEMINI_API_KEY") or "").strip()
    gemini_model = (os.getenv("GEMINI_MODEL") or "gemini-1.5-flash").strip()
    ai_provider = (os.getenv("AI_PROVIDER") or "ollama").strip().lower()

    # Ollama is production AI provider when AI_PROVIDER=ollama (default).
    # Automatic fallback to Gemini or Groq is disabled when AI_PROVIDER=ollama.
    prefer_gemini = (ai_provider == "gemini")
    allow_fallbacks = (ai_provider not in ("ollama", ""))

    if prefer_gemini and gemini_key:
        try:
            logger.info("[%s] Calling Gemini API model=%s", task, gemini_model)
            result = await _call_gemini(prompt, gemini_key, gemini_model)
            if result:
                return result, f"Gemini ({gemini_model})"
            errors.append(f"Gemini ({gemini_model}) returned no usable response.")
        except Exception as exc:
            message = _short_error(exc)
            errors.append(message)
            logger.warning("[%s] Gemini provider failed (%s): %s", task, type(exc).__name__, message)

    # Primary or fallback: Try Ollama
    if base_url:
        try:
            logger.info(
                "[%s] Calling Ollama base_url=%s model=%s",
                task,
                base_url,
                model,
            )
            result = await _call_ollama(prompt, base_url, model, task)
            if result:
                return result, f"Ollama ({model})"
            errors.append("Ollama returned no usable response.")
        except LLMTimeoutError as exc:
            ollama_timed_out = True
            message = _short_error(exc)
            errors.append(message)
            logger.warning(
                "[%s] Ollama provider timed out: %s",
                task,
                message,
            )
        except Exception as exc:
            message = _short_error(exc)
            errors.append(message)
            logger.warning(
                "[%s] Ollama provider failed (%s): %s",
                task,
                type(exc).__name__,
                message,
            )
    elif not prefer_gemini:
        errors.append(
            "OLLAMA_URL is not configured. Set it to an Ollama base URL, "
            "for example http://127.0.0.1:11434 for local inference or your Cloudflare Tunnel URL."
        )
        logger.error("[%s] %s", task, errors[-1])

    # Only attempt fallbacks if allowed (disabled when AI_PROVIDER=ollama)
    if allow_fallbacks:
        groq_key = (os.getenv("GROQ_API_KEY") or "").strip()
        if groq_key:
            result = await _call_groq(prompt, groq_key, task)
            if result:
                return result, "Groq"
            errors.append("Groq provider failed.")

        if not prefer_gemini and gemini_key:
            result = await _call_gemini(prompt, gemini_key, gemini_model)
            if result:
                return result, f"Gemini ({gemini_model})"
            errors.append("Gemini provider failed.")

    detail = "; ".join(errors) or "No AI providers are configured."
    logger.error("[%s] All configured AI providers failed: %s", task, detail)

    if task in ("chat", "patch_generation"):
        error_type = LLMTimeoutError if ollama_timed_out and not (allow_fallbacks and (gemini_key or (os.getenv("GROQ_API_KEY") or "").strip())) else LLMProviderError
        raise error_type(f"All configured AI providers failed. {detail}")

    # Explicit offline status for scanner tasks; this is not a clean security verdict.
    offline_fallback = {
        "is_vulnerable": False,
        "title": "AI analysis unavailable",
        "severity": "info",
        "owasp": "N/A",
        "description": (
            "The configured AI providers were unreachable. Treat this as unavailable "
            "analysis, not as a clean security result."
        ),
        "attack_scenario": "Not assessed because model inference was unavailable.",
        "line_hint": 1,
        "confidence": "low",
        "fix": (
            "Restore the configured Ollama endpoint or tunnel, "
            "then rerun the scan."
        ),
    }
    return json.dumps(offline_fallback), "VibeSec Offline Status (not a security verdict)"
