# VibeSec Production Deployment Guide

This guide contains copy-paste configuration settings for deploying VibeSec across **Netlify** (Frontend), **Render** (Express API Gateway), and **Render** (FastAPI Backend Service).

---

## Architecture Overview

```
[ Browser / Client ]
        |
        v (HTTPS)
[ Netlify: React + Vite SPA ]
        |
        v (HTTPS with strict CORS & X-Session-ID)
[ Render: Express API Gateway ]
  - Rate limiting, SSRF defense, upload sandbox, session filtering
        |
        v (HTTPS with FASTAPI_INTERNAL_TOKEN)
[ Render: FastAPI Backend Service ]
  - Static analysis heuristics, Semgrep, AST rules
  - Production AI: Google Gemini API (gemini-1.5-flash)
  - (Local Dev AI: Ollama qwen2.5-coder:7b preserved)
```

---

## 1. FastAPI Backend Service (Render)

Deploy this service first so its URL is ready for the Express Gateway.

- **Service Type**: Web Service (or Private Service)
- **Environment**: `Python 3`
- **Root Directory**: `vibesec/backend`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Health Check Path**: `/healthz`

### Environment Variables (FastAPI)
| Variable | Value | Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `production` | Enables production provider routing |
| `AI_PROVIDER` | `gemini` | Routes inference to Gemini API |
| `GEMINI_API_KEY` | `AIzaSy...` | Your Google Gemini API key |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Production AI model |
| `FASTAPI_INTERNAL_TOKEN` | *(e.g. `openssl rand -hex 32`)* | Shared secret with Express API |
| `SESSION_SECRET` | *(e.g. `openssl rand -hex 32`)* | Shared HMAC secret for session authentication and history isolation |
| `MONGODB_URI` | *(optional)* | MongoDB Atlas URI (in-memory fallback if omitted) |

---

## 2. Express API Gateway (Render)

- **Service Type**: Web Service
- **Environment**: `Node`
- **Root Directory**: *(leave blank / project root)*
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Health Check Path**: `/healthz`

### Environment Variables (Express)
| Variable | Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Production mode |
| `FASTAPI_URL` | `https://vibesec-backend.onrender.com` | URL of your deployed FastAPI service |
| `FASTAPI_INTERNAL_TOKEN` | *(same token generated above)* | Matches FastAPI internal auth token |
| `SESSION_SECRET` | *(same secret generated above)* | Matches FastAPI session HMAC secret |
| `ALLOWED_ORIGINS` | `https://your-site.netlify.app` | Netlify production origin for strict CORS |
| `GEMINI_API_KEY` | `AIzaSy...` | Your Google Gemini API key |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Production model |

---

## 3. Frontend SPA (Netlify)

- **Site Type**: Static Site (React + Vite)
- **Base Directory**: *(leave blank / project root)*
- **Build Command**: `npm run build`
- **Publish Directory**: `dist`

### Environment Variables (Netlify)
| Variable | Value | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `https://vibesec-api.onrender.com` | URL of your deployed Express API |

> **Note on Routing & Direct Requests**:
> SPA routing is configured automatically via `netlify.toml` and `public/_redirects` (`/* /index.html 200`).
> API requests are made directly from the client browser to the Render Express API with strict CORS and credentials support; requests are **not** proxied through Netlify.

---

## 4. Local Development vs Production AI

- **Local Development**:
  - Run `ollama serve` and ensure `qwen2.5-coder:7b` is pulled (`ollama pull qwen2.5-coder:7b`).
  - `vibesec/backend/.env` defaults to `OLLAMA_URL=http://127.0.0.1:11434` and `OLLAMA_MODEL=qwen2.5-coder:7b`.
  - When running locally, Express runs on port 3000 and FastAPI runs on port 8000.
- **Production**:
  - Sets `AI_PROVIDER=gemini` and `GEMINI_API_KEY`.
  - The LLM chain automatically invokes Google Gemini (`gemini-1.5-flash`) for chat and AI Fix & Verify remediation patches.

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
