"""
VibeSec FastAPI Backend Service
Entry point providing REST endpoints for Code, URL, Upload, and GitHub repository scans.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import os
import uuid
import asyncio
import httpx
import logging
import tempfile
import hmac
import hashlib
import secrets
import json
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, status, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from .scanner.code_scanner import scan_code
    from .scanner.url_scanner import scan_url
    from .scanner.file_scanner import scan_upload
    from .scanner.github_scanner import scan_github, GitHubScanError
    from .database import save_scan_result, get_scan_history, get_scan_by_id
    from .models.llm_chain import (
        OLLAMA_URL, OLLAMA_MODEL, COLAB_NGROK_URL, GROQ_API_KEY, GEMINI_API_KEY,
        call_llm, stream_ollama, get_ollama_config, get_ollama_headers,
        LLMProviderError, LLMTimeoutError, OLLAMA_HEADERS,
    )
    from .remediation import propose_remediation_patch, verify_remediation_patch
    from .scanner.env_detector import is_sensitive_config_file
except ImportError:
    from scanner.code_scanner import scan_code
    from scanner.url_scanner import scan_url
    from scanner.file_scanner import scan_upload
    from scanner.github_scanner import scan_github, GitHubScanError
    from database import save_scan_result, get_scan_history, get_scan_by_id
    from models.llm_chain import (
        OLLAMA_URL, OLLAMA_MODEL, COLAB_NGROK_URL, GROQ_API_KEY, GEMINI_API_KEY,
        call_llm, stream_ollama, get_ollama_config, get_ollama_headers,
        LLMProviderError, LLMTimeoutError, OLLAMA_HEADERS,
    )
    from remediation import propose_remediation_patch, verify_remediation_patch
    from scanner.env_detector import is_sensitive_config_file

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vibesec.api")

app = FastAPI(
    title="VibeSec API - AI-Powered Security Scanner for AI Code",
    version="1.0.0",
    description="NIELIT Gorakhpur Major Project by Kartikey Vishwakarma"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def verify_internal_auth(request: Request, call_next):
    """Enforce FASTAPI_INTERNAL_TOKEN when configured in production."""
    configured_token = os.getenv("FASTAPI_INTERNAL_TOKEN", "").strip()
    if configured_token:
        path = request.url.path
        # Exclude public health checks, docs, and preflight requests
        if (
            path in ("/healthz", "/api/health", "/docs", "/redoc", "/openapi.json")
            or request.method == "OPTIONS"
        ):
            return await call_next(request)

        # Check internal token from header
        token = request.headers.get("x-internal-token", "").strip()
        auth = request.headers.get("authorization", "").strip()
        if not token and auth.lower().startswith("bearer "):
            token = auth[7:].strip()

        if token != configured_token:
            logger.warning("Rejected unauthorized internal request to %s", path)
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Invalid or missing FASTAPI_INTERNAL_TOKEN"}
            )

    return await call_next(request)


@app.get("/healthz")
async def healthz():
    """Production health check probe for Render or orchestration."""
    return {"status": "ok", "service": "vibesec-backend"}


# Cryptographic session authentication secret
SESSION_SECRET = os.getenv("SESSION_SECRET", "vibesec-secret-session-key-change-in-prod-32bytes")


def generate_session_token(session_id: str) -> str:
    """Generate cryptographic HMAC-SHA256 signature token for a session ID."""
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{session_id}.{sig}"


def verify_session_credentials(session_id: Optional[str], session_token: Optional[str]) -> bool:
    """Verify that the session token cryptographically authenticates the session ID."""
    if not session_id or not session_token:
        return False
    session_id = session_id.strip()
    session_token = session_token.strip()

    if "." in session_token:
        parts = session_token.split(".", 1)
        token_sid, sig = parts[0], parts[1]
        if token_sid != session_id:
            return False
    else:
        sig = session_token

    expected_sig = hmac.new(SESSION_SECRET.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)


def get_authenticated_session(request: Request) -> Optional[str]:
    """
    Extract and authenticate session ID from request headers.
    Returns authenticated session_id if valid; None otherwise.
    Does NOT trust client-supplied session ID without a valid signature token.
    """
    raw_sid = request.headers.get("x-session-id") or request.query_params.get("session_id")
    raw_token = (
        request.headers.get("x-session-token")
        or request.headers.get("x-session-signature")
        or request.query_params.get("session_token")
    )

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Session "):
        raw_token = auth_header[8:].strip()
        if "." in raw_token and not raw_sid:
            raw_sid = raw_token.split(".", 1)[0]

    if not raw_sid or not raw_token:
        return None

    if verify_session_credentials(raw_sid, raw_token):
        return raw_sid
    return None


@app.get("/api/session")
async def api_get_session(raw_request: Request, response: Response):
    """Issue or verify an authenticated session token."""
    auth_sid = get_authenticated_session(raw_request)
    if auth_sid:
        token = generate_session_token(auth_sid)
        response.headers["X-Session-ID"] = auth_sid
        response.headers["X-Session-Token"] = token
        return {"session_id": auth_sid, "session_token": token, "authenticated": True}

    new_sid = "vs_" + secrets.token_hex(16)
    new_token = generate_session_token(new_sid)
    response.headers["X-Session-ID"] = new_sid
    response.headers["X-Session-Token"] = new_token
    return {"session_id": new_sid, "session_token": new_token, "authenticated": True}



MAX_CODE_SIZE = 100 * 1024  # 100 KB limit


class CodeScanRequest(BaseModel):
    code: str = Field(..., description="Source code text to audit")
    language: str = Field(default="python", description="Language: python, javascript, typescript, php, java, go")
    filename: Optional[str] = Field(default="snippet.py", description="Optional filename")


class UrlScanRequest(BaseModel):
    url: str = Field(..., description="Target website URL to scan (e.g. https://example.com)")


class GithubScanRequest(BaseModel):
    repo_url: str = Field(..., description="Public GitHub repository URL (e.g. https://github.com/owner/repo)")
    max_files: Optional[int] = Field(default=15, description="Max files to scan")


class ProposePatchRequest(BaseModel):
    vulnerability: Dict[str, Any] = Field(..., description="Target vulnerability metadata")
    code: str = Field(..., description="Source code text containing the vulnerability")
    language: str = Field(default="python", description="Programming language: python, javascript, typescript, php, java, go")
    filename: Optional[str] = Field(default="snippet", description="Filename or identifier")


class VerifyPatchRequest(BaseModel):
    original_code: str = Field(..., description="Original code before patch")
    patched_code: str = Field(..., description="Proposed or user-edited secure patch code")
    vulnerability: Dict[str, Any] = Field(..., description="Target vulnerability metadata")
    language: str = Field(default="python", description="Programming language")
    filename: Optional[str] = Field(default="snippet", description="Filename or identifier")
    user_approved: bool = Field(..., description="Explicit user confirmation to test changes in sandbox")


@app.get("/api/health")
async def health_check():
    """Report API health separately from live Ollama/model availability."""
    active_target, model_name = get_ollama_config()
    ollama_active = False
    model_available = False
    error_message = None

    if not active_target:
        error_message = "OLLAMA_URL is missing or is not a valid HTTP(S) base URL."
    else:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True) as client:
                response = await client.get(
                    f"{active_target}/api/tags",
                    headers=get_ollama_headers(),
                )
            response.raise_for_status()
            data = response.json()
            available_models = data.get("models", []) if isinstance(data, dict) else []
            if not isinstance(available_models, list):
                raise ValueError("Ollama /api/tags returned an invalid model list.")
            ollama_active = True
            model_available = any(
                isinstance(item, dict)
                and (item.get("name") == model_name or item.get("model") == model_name)
                for item in available_models
            )
            if not model_available:
                error_message = f"Ollama is reachable, but model {model_name} is not listed."
        except Exception as exc:
            logger.warning("Ollama health probe failed: %s", type(exc).__name__)
            error_message = f"Ollama health check failed: {type(exc).__name__}."

    return {
        "status": "healthy",
        "service": "VibeSec Security Scanner",
        "author": "Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)",
        "models": {
            "primary": {
                "name": model_name,
                "url": active_target,
                "is_active": ollama_active,
                "model_available": model_available,
                "error": error_message,
            },
            "fallbacks": {
                "groq_configured": bool(os.getenv("GROQ_API_KEY", "").strip()),
                "gemini_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
            },
        },
    }


@app.post("/api/scan/code")
async def api_scan_code(request: CodeScanRequest, raw_request: Request, response: Response):
    """Scan raw code pasted by user."""
    code_bytes = len(request.code.encode("utf-8"))
    if code_bytes > MAX_CODE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Code size exceeds limit of {MAX_CODE_SIZE // 1024}KB"
        )
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code string cannot be empty")

    scan_id = str(uuid.uuid4())
    report = await scan_code(request.code, language=request.language, filename=request.filename or "snippet")
    report["scan_id"] = scan_id
    report["input_type"] = "code"

    authenticated_sid = get_authenticated_session(raw_request)
    if not authenticated_sid:
        authenticated_sid = "vs_" + secrets.token_hex(16)
    session_token = generate_session_token(authenticated_sid)
    report["session_id"] = authenticated_sid
    report["session_token"] = session_token
    response.headers["X-Session-ID"] = authenticated_sid
    response.headers["X-Session-Token"] = session_token

    save_scan_result(report)
    return report


@app.post("/api/scan/url")
async def api_scan_url(request: UrlScanRequest, raw_request: Request, response: Response):
    """Scan target website headers, cookies, and linked JS files."""
    if not request.url or len(request.url.strip()) < 4:
        raise HTTPException(status_code=400, detail="Valid URL must be specified")

    scan_id = str(uuid.uuid4())
    report = await scan_url(request.url)
    report["scan_id"] = scan_id

    authenticated_sid = get_authenticated_session(raw_request)
    if not authenticated_sid:
        authenticated_sid = "vs_" + secrets.token_hex(16)
    session_token = generate_session_token(authenticated_sid)
    report["session_id"] = authenticated_sid
    report["session_token"] = session_token
    response.headers["X-Session-ID"] = authenticated_sid
    response.headers["X-Session-Token"] = session_token

    save_scan_result(report)
    return report


MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB max upload


@app.post("/api/scan/upload")
async def api_scan_upload(raw_request: Request, response: Response, file: UploadFile = File(...)):
    """Upload and scan single source file or ZIP archive up to 100MB with bounded-memory disk spooling."""
    content_length = raw_request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds the maximum allowed limit of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB."
        )

    if getattr(file, "size", None) and file.size > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds the maximum allowed limit of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB."
        )

    # Stream upload in bounded chunks directly to disk to prevent RAM exhaustion
    tmp_file = tempfile.NamedTemporaryFile(delete=False, prefix="vibesec_spool_")
    tmp_path = tmp_file.name
    total_bytes = 0
    chunk_size = 2 * 1024 * 1024  # 2MB chunking for bounded heap memory usage

    try:
        while chunk := await file.read(chunk_size):
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_SIZE:
                tmp_file.close()
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Uploaded file exceeds the maximum allowed limit of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB."
                )
            tmp_file.write(chunk)
        tmp_file.close()

        if total_bytes == 0:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        report = await scan_upload(filename=file.filename or "upload.zip", file_path=tmp_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass

    authenticated_sid = get_authenticated_session(raw_request)
    if not authenticated_sid:
        authenticated_sid = "vs_" + secrets.token_hex(16)
    session_token = generate_session_token(authenticated_sid)
    report["session_id"] = authenticated_sid
    report["session_token"] = session_token
    response.headers["X-Session-ID"] = authenticated_sid
    response.headers["X-Session-Token"] = session_token

    save_scan_result(report)
    return report


@app.post("/api/scan/github")
async def api_scan_github(request: GithubScanRequest, raw_request: Request, response: Response):
    """Scan a public GitHub repository."""
    if "github.com" not in request.repo_url.lower():
        raise HTTPException(status_code=400, detail="Target URL must be a valid GitHub repository")

    try:
        scan_id = str(uuid.uuid4())
        report = await scan_github(request.repo_url, max_files=request.max_files or 15)
        report["scan_id"] = scan_id

        authenticated_sid = get_authenticated_session(raw_request)
        if not authenticated_sid:
            authenticated_sid = "vs_" + secrets.token_hex(16)
        session_token = generate_session_token(authenticated_sid)
        report["session_id"] = authenticated_sid
        report["session_token"] = session_token
        response.headers["X-Session-ID"] = authenticated_sid
        response.headers["X-Session-Token"] = session_token

        save_scan_result(report)
        return report
    except GitHubScanError as e:
        logger.warning(f"GitHub scan error ({type(e).__name__}): {e.message}")
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        logger.error(f"GitHub scan error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/history")
async def api_get_history(raw_request: Request, limit: int = 20):
    """Get scan history strictly isolated and authenticated per user session."""
    client_sid = raw_request.headers.get("x-session-id") or raw_request.query_params.get("session_id")
    client_token = (
        raw_request.headers.get("x-session-token")
        or raw_request.headers.get("x-session-signature")
        or raw_request.query_params.get("session_token")
    )

    auth_header = raw_request.headers.get("authorization", "").strip()
    if auth_header.startswith("Session "):
        tok = auth_header[8:].strip()
        if not client_token:
            client_token = tok
        if not client_sid and "." in tok:
            client_sid = tok.split(".", 1)[0]

    if client_sid and not client_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Client-supplied X-Session-ID cannot be used without a valid X-Session-Token."
        )

    authenticated_sid = get_authenticated_session(raw_request)
    if not authenticated_sid:
        if client_sid or client_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid or forged session authentication credentials."
            )
        return []

    return get_scan_history(limit=limit, session_id=authenticated_sid)


class ChatRequest(BaseModel):
    message: str
    history: List[Dict[str, Any]] = Field(default_factory=list)
    context: Optional[Dict[str, Any]] = None
    stream: Optional[bool] = False


@app.post("/api/chat")
async def chat(req: ChatRequest):
    """Answer a security question via the shared LLM chain (supports streaming)."""
    message = (req.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    def _clip(value: Any, limit: int) -> str:
        """Bound user- and scan-provided text so CPU inference stays responsive."""
        return str(value or "")[:limit]

    ctx = ""
    if req.context:
        ctx = f"""
Current scan context:
Vulnerability: {_clip(req.context.get('type', req.context.get('title', 'Unknown')), 160)}
Severity: {_clip(req.context.get('severity', 'Unknown'), 40)}
Line: {_clip(req.context.get('line', req.context.get('line_hint', 'Unknown')), 40)}
Description: {_clip(req.context.get('description', ''), 600)}
OWASP: {_clip(req.context.get('owasp', ''), 160)}
Suggested fix: {_clip(req.context.get('fix', ''), 600)}
"""

    # Only recent, short history is useful for a one-shot local inference call.
    history_items = []
    for item in (req.history or [])[-4:]:
        if isinstance(item, dict):
            role = _clip(item.get("role", "user"), 16)
            content = _clip(item.get("content", ""), 500)
            if content.strip():
                history_items.append(f"{role}: {content}")
    history_text = "\n".join(history_items)

    prompt = f"""You are VibeSec AI, an application-security assistant integrated into a static
application security testing tool. Explain vulnerabilities accurately and clearly.
For remediation questions, give a practical fix and the smallest secure code example needed.
Do not claim to have executed code or verified a fix unless that actually happened.
Respond in the same language as the user. Use concise prose, not JSON; avoid repeating context.
{ctx}
Recent conversation:
{history_text}
User: {message[:2000]}
Assistant:"""

    # Handle streaming request
    if req.stream:
        async def event_generator():
            try:
                async for chunk in stream_ollama(prompt, task="chat"):
                    yield f"data: {json.dumps({'chunk': chunk, 'done': False})}\n\n"
                yield f"data: {json.dumps({'chunk': '', 'done': True})}\n\n"
                yield "data: [DONE]\n\n"
            except (LLMTimeoutError, asyncio.TimeoutError) as exc:
                logger.warning("Streaming chat timed out: %s", exc)
                yield f"data: {json.dumps({'error': 'AI response timed out. Ensure the Ollama tunnel is running.', 'done': True})}\n\n"
            except Exception as exc:
                logger.warning("Streaming chat error: %s", exc)
                yield f"data: {json.dumps({'error': str(exc), 'done': True})}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )

    try:
        # Leave margin above Ollama's 75s read timeout for queueing and serialization.
        answer, model_used = await asyncio.wait_for(
            call_llm(prompt, task="chat"),
            timeout=90.0,
        )
    except asyncio.TimeoutError as exc:
        logger.warning("Chat inference exceeded the 90-second application deadline")
        raise HTTPException(
            status_code=504,
            detail="AI response timed out. Check that the configured Ollama service is running, then retry with a shorter question.",
        ) from exc
    except LLMTimeoutError as exc:
        logger.warning("Chat inference timed out: %s", str(exc)[:600])
        raise HTTPException(
            status_code=504,
            detail=f"VibeSec AI timed out while contacting its model provider: {str(exc)[:500]}",
        ) from exc
    except LLMProviderError as exc:
        logger.warning("Chat provider chain failed: %s", str(exc)[:600])
        raise HTTPException(
            status_code=502,
            detail=f"VibeSec AI could not generate a response: {str(exc)[:600]}",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected VibeSec chat failure")
        raise HTTPException(
            status_code=502,
            detail="VibeSec AI encountered an unexpected provider error. Check the backend log for details.",
        ) from exc

    if not isinstance(answer, str) or not answer.strip():
        raise HTTPException(status_code=502, detail="The AI provider returned an empty response.")

    return {
        "response": answer.strip(),
        "reply": answer.strip(),
        "model": model_used,
    }


@app.post("/api/chat/stream")
async def chat_stream(req: ChatRequest):
    """Explicit streaming chat endpoint via Server-Sent Events (SSE)."""
    req.stream = True
    return await chat(req)


@app.get("/api/scan/{scan_id}")
async def api_get_scan(scan_id: str, raw_request: Request):
    """Retrieve full scan details by ID with session ownership authorization."""
    result = get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan report not found")

    scan_session_id = result.get("session_id")
    if scan_session_id:
        authenticated_sid = get_authenticated_session(raw_request)
        if not authenticated_sid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Valid session authentication required to access this scan report."
            )
        if authenticated_sid != scan_session_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have permission to access another session's scan report."
            )

    return result


@app.post("/api/remediate/propose-patch")
async def api_propose_patch(req: ProposePatchRequest):
    """
    AI Remediation Copilot: Generate proposed secure patch using local Ollama model.
    Validates patch structure and scope against the submitted code.
    """
    code_text = (req.code or "").strip()
    if not req.vulnerability:
        raise HTTPException(status_code=400, detail="Vulnerability details are required.")
    if len(code_text.encode("utf-8")) > MAX_CODE_SIZE:
        raise HTTPException(status_code=413, detail="Code exceeds maximum allowed size.")

    snippet = (req.vulnerability.get("code_snippet") or "").strip()
    vuln_title = (req.vulnerability.get("title") or "").lower()
    vuln_file = (req.vulnerability.get("file") or "").lower()
    is_file_level = (
        "environment file" in vuln_title
        or ".env" in vuln_file
        or "template" in vuln_title
        or is_sensitive_config_file(vuln_file)
        or not snippet
    )

    if not code_text and not is_file_level:
        raise HTTPException(status_code=400, detail="Source code cannot be empty.")

    result = await propose_remediation_patch(
        vulnerability=req.vulnerability,
        code=req.code,
        language=req.language,
        filename=req.filename or "snippet"
    )
    return result


@app.post("/api/remediate/verify-patch")
async def api_verify_patch(req: VerifyPatchRequest):
    """
    AI Remediation Copilot: Isolated Deterministic Retesting.
    Applies approved changes only to an isolated temporary sandbox and reruns scanner rules.
    Requires explicit user approval.
    """
    if not req.user_approved:
        raise HTTPException(
            status_code=400,
            detail="Explicit user approval is required before applying and verifying changes."
        )
    if not req.original_code or not req.original_code.strip():
        raise HTTPException(status_code=400, detail="Original code cannot be empty.")
    if not req.patched_code or not req.patched_code.strip():
        raise HTTPException(status_code=400, detail="Patched code cannot be empty.")

    result = verify_remediation_patch(
        original_code=req.original_code,
        patched_code=req.patched_code,
        vulnerability=req.vulnerability,
        language=req.language,
        filename=req.filename or "snippet",
        user_approved=req.user_approved
    )
    return result


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
