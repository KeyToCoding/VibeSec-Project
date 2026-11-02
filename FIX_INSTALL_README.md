VibeSec end-to-end chatbot repair patch

Contents in this archive:
- server.ts
- vibesec/backend/main.py
- vibesec/backend/models/llm_chain.py
- vibesec/frontend/components/SecurityBot.tsx

Installation
1. Back up your project before replacing files.
2. Extract this archive into the VibeSec project root (the folder containing server.ts).
3. Do NOT replace your private vibesec/backend/.env with a shared/template file. This archive intentionally omits .env because it may contain API keys and database credentials.
4. In your existing vibesec/backend/.env, check that these are present and have no API suffix:
   OLLAMA_URL=https://defiance-deacon-speculate.ngrok-free.dev
   OLLAMA_MODEL=qwen2.5-coder:7b
   The OLLAMA_URL should end at the host, not at /api/tags or /api/generate.
   COLAB_NGROK_URL is optional; the fixed code uses OLLAMA_URL as canonical and only falls back to COLAB_NGROK_URL when OLLAMA_URL is blank.
5. Keep the Colab notebook running with the ngrok tunnel forwarding to localhost:11434.
6. Restart FastAPI in Terminal 1:
   cd "C:\Users\karti\OneDrive\Desktop\NIELIT Gorakhpur\vibesec\backend"
   python -m uvicorn main:app --reload --port 8000
7. Restart the root app in Terminal 2:
   cd "C:\Users\karti\OneDrive\Desktop\NIELIT Gorakhpur"
   npm run dev
8. Verify:
   curl.exe http://127.0.0.1:8000/api/health
   Then test the chatbot through http://localhost:3000.

Verified in the patch workspace:
- Python syntax compilation: pass.
- Mocked LLM-chain tests (URL normalization, ngrok header, non-streaming chat payload, successful Ollama response contract): pass.
- FastAPI TestClient tests (chat success contract, provider failure returns HTTP 502, blank message returns HTTP 400): pass.
- TypeScript `npm run lint` (`tsc --noEmit`): pass.

Not verified here:
- Live browser / Windows FastAPI / Colab tunnel flow. This execution environment could not resolve the public ngrok hostname.
- Vite production build. The mounted node_modules archive was built for Windows and lacked the Linux Rolldown native binding in this workspace. This is an environment/dependency issue; run npm install/npm ci on your Windows project before building there.
