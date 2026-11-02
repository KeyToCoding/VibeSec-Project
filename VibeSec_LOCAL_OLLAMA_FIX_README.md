# VibeSec local Ollama timeout fix

This patch is based on the uploaded `NIELIT Gorakhpur` project. It contains only the three source files changed to address long chatbot prompts timing out while the local `qwen2.5-coder:7b` Ollama API is healthy.

## Root cause identified from the uploaded code and the reported logs

- Direct local Ollama generation of a very short prompt succeeded in about 0.45 seconds, so the local API is reachable.
- The backend log reported an Ollama `ReadTimeout` at about 52 seconds for chat requests.
- `llm_chain.py` allowed up to 384 generated tokens for chat. A short test returning `OK` does not represent the cost of a longer vulnerability explanation/code answer on CPU.
- The chat prompt included up to eight previous messages of 1,000 characters each, plus unbounded vulnerability descriptions/fixes and a 4,000-character current message.
- The timeout UI text still mentioned Colab/ngrok even when `OLLAMA_URL` pointed at local Ollama, which obscured the actual cause.

## Files in this patch

- `vibesec/backend/models/llm_chain.py`
  - Reduces chat `num_predict` from 384 to 160; scan-analysis generation keeps its existing 512-token limit.
  - Provides local-vs-remote timeout guidance.
  - Removes misleading ngrok-only messages from configuration/offline errors.

- `vibesec/backend/main.py`
  - Bounds vulnerability context, conversation history, and current message length to reduce prefill work.
  - Asks the model for concise remediation answers with only the smallest secure code example needed.
  - Uses a provider-neutral timeout message.

- `vibesec/frontend/components/SecurityBot.tsx`
  - Removes the stale Colab/ngrok wording from the frontend timeout error.

`server.ts` was inspected and left unchanged: its `/api/chat` route already forwards FastAPI's HTTP status/body and uses a 65-second timeout, which is longer than the backend's 52-second Ollama read timeout and 57-second FastAPI chat deadline.

## Apply the patch

1. Stop FastAPI with `Ctrl+C` in its terminal.
2. Back up the three existing files.
3. Extract this ZIP into the project root `C:\Users\ISEA\Desktop\NIELIT Gorakhpur\`, preserving folder structure and allowing the three files to be replaced.
4. Keep your private `vibesec/backend/.env` file. It is intentionally not included in this ZIP.
5. Confirm the Ollama lines in `vibesec/backend/.env` are:

   ```dotenv
   OLLAMA_URL=http://127.0.0.1:11434
   OLLAMA_MODEL=qwen2.5-coder:7b
   ```

6. Restart FastAPI:

   ```powershell
   cd "C:\Users\ISEA\Desktop\NIELIT Gorakhpur\vibesec\backend"
   .\.venv\Scripts\Activate.ps1
   python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```

7. Keep Ollama running on port 11434 and keep the existing frontend terminal running at port 3000.
8. Test a general question and then click `How to fix this?` on a detected vulnerability.

## Verification performed here

- Python syntax compilation passed for the patched `main.py` and `llm_chain.py`.
- A live end-to-end request against the user's Windows Ollama/FastAPI environment cannot be executed from this environment. The user's own direct Ollama test succeeded; after applying this patch, re-run the FastAPI and browser tests on the PC.

The patch does not include `.env`, API credentials, `.venv`, or `node_modules`.
