VibeSec One-Click Local Startup Bundle

INSTALL
1. Extract the contents of this ZIP directly into your existing project root:
   C:\Users\ISEA\Desktop\NIELIT Gorakhpur
2. Merge the new scripts folder with your existing scripts folder. Do not replace existing project files.
3. The bundle adds only these new files:
   Start-VibeSec-Stack.bat
   scripts\Launch-VibeSec-Stack.ps1
   scripts\Run-VibeSec-Tunnel.ps1
   scripts\Show-VibeSec-Connection.ps1
4. Double-click Start-VibeSec-Stack.bat.

WHAT IT DOES
- Checks Ollama and starts `ollama serve` in a separate terminal only if Ollama is offline.
- Reuses the authenticated proxy if it is already working; otherwise opens the existing Start-Ollama-Proxy.ps1 in a separate terminal.
- Opens Cloudflare Quick Tunnel in its own terminal and saves the public URL under logs\cloudflare-url.txt (logs are gitignored).
- Opens a separate connection-details terminal. Press U to copy OLLAMA_URL or T to copy the proxy token. The complete token is never printed.
- Runs the existing Start-VibeSec.ps1 and opens http://localhost:3000.

IMPORTANT
- Requires existing scripts\Start-Ollama-Proxy.ps1 and scripts\Start-VibeSec.ps1.
- Requires Ollama, cloudflared, Node dependencies, and the backend virtual environment already installed.
- Keep the Ollama, proxy, and Cloudflare terminals open while hosted AI uses your PC.
- A Cloudflare Quick Tunnel URL can change after a restart. Update Render OLLAMA_URL with the new URL when that happens.
- Token is read from scripts\.proxy_token and is not included in this ZIP.
- This bundle does not edit Render, GitHub, .env files, or project configuration.
- If an older manually-started Cloudflare tunnel for port 11435 is running, stop it with Ctrl+C first, then run the launcher.
