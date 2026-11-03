# VibeSec production reliability fix

This patch addresses the November 3, 2026 Render logs.

## Root cause
`scan_code()` is an async FastAPI handler but called the Semgrep CLI synchronously.
When Semgrep reached its 30-second timeout, it blocked the single FastAPI event loop.
That prevented unrelated requests such as `/api/chat` from progressing, which caused
the chat application deadline and Express proxy timeout to fire.

## Changes
- Run Semgrep with `asyncio.to_thread()` so its CLI process cannot block FastAPI's event loop.
- Align model, FastAPI, Express, and browser chat timeouts: Ollama 75s read timeout,
  FastAPI 90s, Express 100s, browser 110s.
- Give the Express code-scan proxy up to 150s for Semgrep plus a bounded local-model verification.
- Use Ollama's JSON-schema constrained output for vulnerability analysis, with concise field instructions.
- Parse only the first complete JSON object and preserve the static finding when model JSON is malformed.
- Avoid repeated connection attempts to `localhost:27017` when `MONGODB_URI` is not configured.
  The application still uses in-memory server history in that case; it is not durable.

## Validation needed after applying
Run the backend tests, TypeScript check, and frontend production build locally.
Then commit/push these changes and redeploy both Render services because `server.ts`
and backend files have changed. Netlify only needs a new deploy if the frontend source was changed.
