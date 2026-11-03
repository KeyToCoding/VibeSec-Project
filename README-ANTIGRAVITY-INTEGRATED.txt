VibeSec — Antigravity Integrated Terminal Startup
==================================================

This bundle adds Antigravity/VS Code tasks that launch VibeSec in the IDE's
integrated Terminal panel. It does not intentionally open separate Windows
PowerShell windows.

INSTALL
-------
1. Open your existing project folder:
   C:\Users\ISEA\Desktop\NIELIT Gorakhpur
2. Extract this ZIP into that folder and choose merge/overwrite if asked.
   It adds .vscode\tasks.json and five uniquely named scripts under scripts\.
3. If the project already has .vscode\tasks.json, back it up before replacing.
4. In Antigravity, reload the window (Ctrl+Shift+P > Developer: Reload Window).
5. Use Terminal > Run Build Task, then select:
   VibeSec: Start All (Antigravity Integrated)
   Or press Ctrl+Shift+B if it is the default build task.

EXPECTED INTEGRATED TERMINALS
-----------------------------
1. VibeSec: 1 - Ollama
2. VibeSec: 2 - Authenticated Proxy
3. VibeSec: 3 - Cloudflare Tunnel
4. VibeSec: 4 - Connection Details (URL + Token)
5. VibeSec: 5 - App + Logs

The connection-details terminal waits for Cloudflare to provide its temporary
URL, then automatically displays OLLAMA_URL and OLLAMA_PROXY_TOKEN. No U/T
keypress is required. The complete token is shown only in that local terminal
because the operator requested it. Do not screenshot/share that terminal,
stream your screen while it is visible, or paste the token into chat, source
code, logs, or GitHub. Keep scripts/.proxy_token ignored by Git.

CLOUDFLARE POWERSHELL 5.1 FIX
----------------------------
The tunnel runner uses Start-Process with stdout/stderr redirected to ignored
local logs, then tails those files from the integrated terminal. This avoids
piping cloudflared's native stderr through PowerShell 5.1 (the prior
NativeCommandError issue).

STOPPING
--------
- In each long-running task terminal, press Ctrl+C to stop that task.
- Run task "VibeSec: Stop Local App Services" to stop the FastAPI/Express
  processes managed by scripts/Start-VibeSec.ps1.
- Ollama itself may be managed by its Windows app. Stopping the monitor task
  does not stop an already running Ollama Windows service.

NOTES
-----
- Requires existing scripts/Start-Ollama-Proxy.ps1, scripts/Start-VibeSec.ps1,
  scripts/Stop-VibeSec.ps1, scripts/ollama_proxy.py and backend .venv.
- Uses Windows PowerShell 5.1 intentionally.
- Cloudflare Quick Tunnel URLs are temporary and can change after restart.
- This is a local developer convenience, not a durable production tunnel.
- This bundle only adds files. It does not change application source, Git
  history, Git identity, Render variables, or Netlify configuration.
