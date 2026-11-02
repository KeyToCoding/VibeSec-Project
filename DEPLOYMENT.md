# VibeSec Zero-Cost Production Deployment Guide

This guide details the complete configuration for running VibeSec with **100% free, zero-cost services**:
- **Netlify Free Tier** (React + Vite Static SPA)
- **Render Free Tier** (Express API Gateway)
- **Render Free Tier** (FastAPI Backend Service)
- **Cloudflare Quick Tunnel** (Free HTTPS tunnel with zero domain or account needed)
- **Local Windows Ollama** (`qwen2.5-coder:7b` via an authenticated security proxy)

No paid cloud subscriptions, custom domains, or paid AI API keys are required.

---

## Zero-Cost Architecture Overview

```
[ Browser / Client ]
        │
        ▼ (HTTPS)
[ Netlify Free: React + Vite SPA ]
        │
        ▼ (HTTPS with strict CORS, credentials & session tracking)
[ Render Free: Express API Gateway ]
        │ - Rate limiting, SSRF defense, upload sanitization
        │ - Internal auth token validation
        ▼ (HTTPS with FASTAPI_INTERNAL_TOKEN)
[ Render Free: FastAPI Backend Service ]
        │ - Static analysis heuristics, Semgrep, AST rules
        │ - Session isolation & patch verification sandbox
        │ - AI Provider: Ollama (AI_PROVIDER=ollama, Model: qwen2.5-coder:7b)
        ▼ (HTTPS with OLLAMA_PROXY_TOKEN via Cloudflare Quick Tunnel)
[ Cloudflare Quick Tunnel (Free, no account needed) ]
        │
        ▼ (HTTP localhost:11435)
[ Local Authenticated Windows Proxy (scripts/ollama_proxy.py) ]
        │ - Constant-time token verification (OLLAMA_PROXY_TOKEN)
        │ - Strict endpoint whitelisting (/api/generate, /api/chat, /api/tags)
        │ - Rate limiting (60 req/min) & SSE token streaming
        ▼ (HTTP localhost:11434)
[ Local Ollama on Windows (qwen2.5-coder:7b) ]
```

---

## 1. Local Windows Setup (Ollama, Security Proxy & Cloudflare Tunnel)

### Step 1: Install & Verify Ollama
1. Download Ollama for Windows from [ollama.com](https://ollama.com).
2. Pull the production security model:
   ```powershell
   ollama pull qwen2.5-coder:7b
   ```
3. Ensure Ollama is running at `http://127.0.0.1:11434`.

### Step 2: Configure & Start the Authenticated Local Proxy
The repository includes a dedicated lightweight proxy (`scripts/ollama_proxy.py`) that protects your local Ollama instance:
- **Token Protection**: Enforces `Authorization: Bearer <OLLAMA_PROXY_TOKEN>` or `X-Ollama-Proxy-Token`.
- **Endpoint Whitelisting**: Only allows safe inference (`/api/generate`, `/api/chat`, `/api/tags`, `/api/version`). Blocks administrative operations (`/api/pull`, `/api/delete`, `/api/create`).
- **Rate Limiting**: Defends against runaway traffic or brute force (default 60 requests/minute).
- **Streaming & Timeouts**: Forwards SSE token streams and handles connection resets gracefully.

Generate a strong random proxy token:
```powershell
# In PowerShell:
$Token = [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
$env:OLLAMA_PROXY_TOKEN = $Token
Write-Host "Your OLLAMA_PROXY_TOKEN is: $Token"
```

Start the proxy using the automated helper script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-Ollama-Proxy.ps1 -Token $Token
```
*(By default, the proxy listens on `127.0.0.1:11435` and forwards to `127.0.0.1:11434`)*.

### Step 3: Start Cloudflare Quick Tunnel (Free, No Domain/Account Required)
1. Download `cloudflared` for Windows (or install via `winget install Cloudflare.cloudflared`).
2. Start an ephemeral HTTPS quick tunnel targeting your proxy port:
   ```powershell
   cloudflared tunnel --url http://127.0.0.1:11435
   ```
3. Cloudflare will print an assigned HTTPS URL in the console, for example:
   ```
   https://random-assigned-subdomain.trycloudflare.com
   ```
4. This HTTPS URL is your production `OLLAMA_URL`.

---

## 2. FastAPI Backend Service (Render Free)

Deploy this service so its URL is ready for the Express Gateway.

- **Service Type**: Web Service
- **Environment**: `Python 3`
- **Root Directory**: `vibesec/backend`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Health Check Path**: `/healthz`

### Environment Variables (FastAPI on Render)
| Variable | Value | Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `production` | Production mode |
| `AI_PROVIDER` | `ollama` | **Production AI Provider (Zero-Cost, no paid API needed)** |
| `OLLAMA_URL` | `https://random-subdomain.trycloudflare.com` | Cloudflare Quick Tunnel HTTPS URL |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | Production coding and security model |
| `OLLAMA_PROXY_TOKEN` | *(same secret token generated above)* | Bearer token to authenticate with your Windows proxy |
| `FASTAPI_INTERNAL_TOKEN` | *(e.g. `openssl rand -hex 32`)* | Shared secret with Express API Gateway |
| `SESSION_SECRET` | *(e.g. `openssl rand -hex 32`)* | Shared HMAC secret for session authentication and history isolation |
| `GEMINI_API_KEY` | *(leave empty)* | **Optional**. When `AI_PROVIDER=ollama`, Gemini fallback is disabled. |

---

## 3. Express API Gateway (Render Free)

- **Service Type**: Web Service
- **Environment**: `Node`
- **Root Directory**: *(leave blank / project root)*
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Health Check Path**: `/healthz`

### Environment Variables (Express on Render)
| Variable | Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Production mode |
| `FASTAPI_URL` | `https://vibesec-backend.onrender.com` | URL of your deployed FastAPI service on Render |
| `FASTAPI_INTERNAL_TOKEN` | *(same token generated above)* | Matches FastAPI internal auth token |
| `SESSION_SECRET` | *(same secret generated above)* | Matches FastAPI session HMAC secret |
| `ALLOWED_ORIGINS` | `https://your-site.netlify.app` | Netlify production origin for strict CORS |

---

## 4. Frontend SPA (Netlify Free)

- **Site Type**: Static Site (React + Vite)
- **Base Directory**: *(leave blank / project root)*
- **Build Command**: `npm run build`
- **Publish Directory**: `dist`

### Environment Variables (Netlify)
| Variable | Value | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `https://vibesec-api.onrender.com` | URL of your deployed Express API Gateway |

> **Security Note on Tokens**:
> `OLLAMA_PROXY_TOKEN` and `FASTAPI_INTERNAL_TOKEN` are strictly backend secrets. They are **never** configured in Netlify or exposed to client-side JavaScript. All client requests flow through Express and FastAPI.

---

## 5. Local Development vs Zero-Cost Production AI

- **Local Development**:
  - Run Ollama locally on `127.0.0.1:11434`.
  - Express runs on port 3000 and FastAPI runs on port 8000.
  - Set `OLLAMA_URL=http://127.0.0.1:11434` in `vibesec/backend/.env`.
- **Zero-Cost Production**:
  - Set `AI_PROVIDER=ollama`.
  - FastAPI on Render routes inference to your Windows Ollama through the Cloudflare Quick Tunnel and authenticated proxy.
  - All AI features (Code Scan Explanations, AI Security Assistant chatbot with streaming, AI Fix & Verify patch generation) run on `qwen2.5-coder:7b`.
  - Gemini API key is not required. Automatic Gemini fallback is disabled when `AI_PROVIDER=ollama`.

---

## 5. Security Checklist

- [x] **SSRF Defense**: Target URL scanner performs DNS pre-resolution and blocks RFC 1918, loopback, link-local, and cloud metadata IP ranges (`169.254.169.254`).
- [x] **Zip-Slip & Zip-Bomb Defense**: Archive extraction verifies target subpaths remain within temporary sandbox and bounds uncompressed payload size (100MB upload limit, 250MB uncompressed limit, 500 files ceiling).
- [x] **Command Injection Defense**: GitHub scan endpoint validates URL format and repo names against injection syntax.
- [x] **Session Isolation**: Client sessions generate and store unique session IDs (`X-Session-ID`), isolating history queries so users cannot inspect other users' scan records.
- [x] **Internal Service Protection**: FastAPI rejects any requests lacking the `FASTAPI_INTERNAL_TOKEN` (while keeping `/healthz` accessible for Render probes).
- [x] **Secrets Hygiene**: `.gitignore` excludes all `.env*` files, while preserving `.env.example` templates.

---

## 6. Large Upload Limits & Cloud Platform Constraints

### Upload Limits Configured in VibeSec
- **Individual Upload Size**: **100 MB** maximum (enforced in frontend, Express gateway, and FastAPI).
- **Uncompressed Archive Expansion**: **250 MB** maximum uncompressed safety ceiling.
- **Maximum Extracted File Count**: **500 files** ceiling (excess files safely skipped with an alert).

### Netlify Considerations
- **Do Not Proxy Uploads Through Netlify**: Netlify Functions enforce a hard **6 MB request body limit** and a 10–26 second timeout.
- The VibeSec architecture directs all browser API calls straight to the Render Express API via `VITE_API_BASE_URL`. Netlify only serves the static SPA bundle, completely bypassing Netlify's 6MB ceiling.

### Render Considerations
- **HTTP Request Timeout (Up to 100 Minutes)**: Render documents that HTTP requests can run for up to **100 minutes** before being terminated. To match this capability, Express socket timeouts and proxy fetch signals have been raised to **10 minutes** (`600,000 ms`), so slow client connections (e.g. 5 Mbps uplinks) and large repository audits are not aborted prematurely.
- **Memory (RAM) Footprint & Zero-RAM Disk Spooling**:
  - FastAPI and Express stream incoming uploads directly into disk-backed ephemeral temporary files in 8 MB chunks instead of buffering 100 MB in process heap. This keeps active RAM usage flat (< 25 MB) during file ingestion.
  - Decompressed archive files are stored on disk (`/tmp`) and inspected individually with AST heuristics before being cleaned up in a `finally` block (`shutil.rmtree`).
  - While single scans will comfortably operate within the **512 MB Free tier limit**, concurrent multi-user scans on large codebases can lead to memory pressure. A **1 GB or 2 GB RAM** instance is recommended for production concurrency.
- **Disk Space**: Render provides ephemeral disk storage that automatically frees space when temporary files are unlinked.
