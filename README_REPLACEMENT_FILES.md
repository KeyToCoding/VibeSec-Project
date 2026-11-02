# VibeSec complete replacement source files

This package contains complete source files (not patches) taken from the latest uploaded project, with the backend `main.py` and `models/llm_chain.py` aligned to one another.

## Included files

- `server.ts`
- `vibesec/backend/main.py`
- `vibesec/backend/models/llm_chain.py`
- `vibesec/frontend/components/SecurityBot.tsx`
- `src/components/SecurityBot.tsx` (the app's re-export entry point)

## Install

1. Extract this ZIP into the root of your VibeSec project and allow the listed files to be replaced.
2. Keep your existing `vibesec/backend/.env`. This package intentionally does not include your actual `.env` or credentials.
3. Ensure `vibesec/backend/.env` contains a current Colab/ngrok base URL and model name:

   ```dotenv
   OLLAMA_URL=https://YOUR-CURRENT-NGROK-URL
   OLLAMA_MODEL=qwen2.5-coder:7b
   ```

   Do not append `/api/tags` or `/api/generate` to `OLLAMA_URL`. Copy the live URL from the currently running Colab tunnel cell.
4. Start Colab's Ollama server and ngrok tunnel first. Verify both `/api/tags` and `/api/generate` through the current public URL.
5. Restart FastAPI in one terminal:

   ```powershell
   cd "C:\Users\karti\OneDrive\Desktop\NIELIT Gorakhpur\vibesec\backend"
   python -m uvicorn main:app --reload --port 8000
   ```

6. Start Express/Vite in a second terminal:

   ```powershell
   cd "C:\Users\karti\OneDrive\Desktop\NIELIT Gorakhpur"
   npm run dev
   ```

## Verification limits

The Python files are syntax-checked. This package does not claim the live tunnel or browser UI was tested by the package-creation environment. A Colab/ngrok `ERR_NGROK_3200` means the tunnel is offline; code changes alone cannot make an offline tunnel work.
