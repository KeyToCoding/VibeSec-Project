/**
 * VibeSec Frontend API Configuration
 *
 * Manages environment-based API base URL (VITE_API_BASE_URL) for production
 * deployments (Netlify frontend -> Render Express API) and relative path fallback
 * for local development.
 *
 * Also handles anonymous per-user session ID tracking to prevent cross-user scan history leakage.
 */

// Production API base URL provided via Netlify environment variables (e.g., https://vibesec-api.onrender.com)
export const API_BASE_URL: string = (
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
  ''
).replace(/\/+$/, '');

/**
 * Returns full URL for an API endpoint path.
 * If VITE_API_BASE_URL is configured, prepends it; otherwise returns relative path.
 */
export function getApiUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${cleanPath}`;
}

/**
 * Retrieves or initializes an anonymous, persistent session credential in localStorage.
 * Uses cryptographic server-signed tokens to isolate scan history per browser/user.
 */
export function getSessionCredentials(): { sessionId: string; sessionToken: string } {
  if (typeof window === 'undefined') {
    return { sessionId: 'session_guest', sessionToken: '' };
  }
  try {
    const sessionId = localStorage.getItem('vibesec_session_id') || '';
    const sessionToken = localStorage.getItem('vibesec_session_token') || '';
    return { sessionId, sessionToken };
  } catch {
    return { sessionId: 'session_guest', sessionToken: '' };
  }
}

export function setSessionCredentials(sessionId: string, sessionToken: string) {
  if (typeof window === 'undefined') return;
  try {
    if (sessionId) localStorage.setItem('vibesec_session_id', sessionId);
    if (sessionToken) localStorage.setItem('vibesec_session_token', sessionToken);
  } catch {}
}

export function saveSessionFromResponse(data?: any, headers?: Headers) {
  if (headers) {
    const sid = headers.get('x-session-id') || headers.get('X-Session-ID');
    const tok = headers.get('x-session-token') || headers.get('X-Session-Token');
    if (sid && tok) {
      setSessionCredentials(sid, tok);
      return;
    }
  }
  if (data && typeof data === 'object') {
    const sid = data.session_id;
    const tok = data.session_token;
    if (sid && tok) {
      setSessionCredentials(sid, tok);
    }
  }
}

/**
 * Initializes or verifies the session with the server.
 */
export async function ensureAuthenticatedSession(): Promise<{ sessionId: string; sessionToken: string }> {
  const current = getSessionCredentials();
  if (current.sessionId && current.sessionToken) {
    return current;
  }
  try {
    const res = await fetch(getApiUrl('/api/session'), {
      headers: current.sessionId ? { 'X-Session-ID': current.sessionId, 'X-Session-Token': current.sessionToken } : {},
    });
    if (res.ok) {
      const data = await res.json();
      if (data.session_id && data.session_token) {
        setSessionCredentials(data.session_id, data.session_token);
        return { sessionId: data.session_id, sessionToken: data.session_token };
      }
    }
  } catch {}
  return current;
}

export function getSessionId(): string {
  return getSessionCredentials().sessionId || 'session_guest';
}

/**
 * Helper to construct standard API request headers including authenticated session credentials.
 */
export function getApiHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  const { sessionId, sessionToken } = getSessionCredentials();
  const headers: Record<string, string> = { ...extraHeaders };
  if (sessionId) {
    headers['X-Session-ID'] = sessionId;
  }
  if (sessionToken) {
    headers['X-Session-Token'] = sessionToken;
  }
  return headers;
}
