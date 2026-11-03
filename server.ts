import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import dns from 'dns';
import crypto from 'crypto';
import { Readable } from 'stream';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import JSZip from 'jszip';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const FASTAPI_URL = (process.env.FASTAPI_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
const FASTAPI_INTERNAL_TOKEN = (process.env.FASTAPI_INTERNAL_TOKEN || '').trim();
const GEMINI_MODEL = (process.env.GEMINI_MODEL || 'gemini-2.5-flash').trim();

// Strict CORS middleware for Render Express API
app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  const configuredOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim().toLowerCase())
    : [];
  const defaultLocalOrigins = [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
  ];

  const isAllowed =
    !origin ||
    process.env.NODE_ENV !== 'production' ||
    configuredOrigins.includes('*') ||
    (origin && configuredOrigins.includes(origin.toLowerCase())) ||
    defaultLocalOrigins.includes(origin.toLowerCase());

  if (origin && isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Accept, X-Requested-With, X-Session-ID, X-Session-Token, X-Session-Signature'
    );
    res.setHeader('Access-Control-Expose-Headers', 'X-Session-ID, X-Session-Token');
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ extended: true, limit: '150mb' }));

// Cryptographic session authentication secret
const SESSION_SECRET = process.env.SESSION_SECRET || 'vibesec-secret-session-key-change-in-prod-32bytes';

function generateSessionToken(sessionId: string): string {
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  return `${sessionId}.${sig}`;
}

function verifySessionCredentials(sessionId?: string, sessionToken?: string): boolean {
  if (!sessionId || !sessionToken) return false;
  sessionId = sessionId.trim();
  sessionToken = sessionToken.trim();

  let sig = sessionToken;
  if (sessionToken.includes('.')) {
    const parts = sessionToken.split('.');
    if (parts[0] !== sessionId) return false;
    sig = parts.slice(1).join('.');
  }

  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  if (sig.length !== expectedSig.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'utf-8'), Buffer.from(expectedSig, 'utf-8'));
  } catch {
    return false;
  }
}

function getAuthenticatedSession(req: Request): string | null {
  const rawSid = ((req.headers['x-session-id'] as string) || (req.query.session_id as string) || '').trim();
  let rawToken = ((req.headers['x-session-token'] as string) || (req.headers['x-session-signature'] as string) || (req.query.session_token as string) || '').trim();

  const authHeader = (req.headers['authorization'] as string) || '';
  if (authHeader.startsWith('Session ')) {
    rawToken = authHeader.substring(8).trim();
  }

  if (!rawSid || !rawToken) return null;
  return verifySessionCredentials(rawSid, rawToken) ? rawSid : null;
}

function getSessionIdFromReq(req: Request): string | null {
  const authSid = getAuthenticatedSession(req);
  if (authSid) return authSid;
  const rawSid = ((req.headers['x-session-id'] as string) || (req.query.session_id as string) || '').trim();
  return rawSid || null;
}

// Helper: Headers sent from Express to FastAPI with internal auth token and authenticated session
function getInternalHeaders(reqOrExtra?: Request | Record<string, string>, extraHeaders: Record<string, string> = {}): Record<string, string> {
  let req: Request | undefined;
  let extras = extraHeaders;

  if (reqOrExtra && typeof (reqOrExtra as any).get === 'function') {
    req = reqOrExtra as Request;
  } else if (reqOrExtra) {
    extras = { ...(reqOrExtra as Record<string, string>), ...extraHeaders };
  }

  const headers: Record<string, string> = { ...extras };
  if (FASTAPI_INTERNAL_TOKEN) {
    headers['X-Internal-Token'] = FASTAPI_INTERNAL_TOKEN;
  }
  if (req) {
    const sid = (req.headers['x-session-id'] as string) || '';
    const tok = (req.headers['x-session-token'] as string) || '';
    if (sid) headers['X-Session-ID'] = sid;
    if (tok) headers['X-Session-Token'] = tok;
  }
  return headers;
}

function resolveSessionForScan(req: Request, res: Response): { sessionId: string; sessionToken: string } {
  let authSid = getAuthenticatedSession(req);
  if (!authSid) {
    authSid = 'vs_' + crypto.randomBytes(16).toString('hex');
  }
  const token = generateSessionToken(authSid);
  res.setHeader('X-Session-ID', authSid);
  res.setHeader('X-Session-Token', token);
  return { sessionId: authSid, sessionToken: token };
}

// In-memory scan ledger for history
interface ScanRecord {
  scan_id: string;
  created_at: string;
  session_id?: string;
  session_token?: string;
  input_type: string;
  target?: string;
  filename?: string;
  vulnerabilities: any[];
  hallucinated_packages?: any[];
  severity_counts: { critical: number; high: number; medium: number; low: number; safe: number };
  files_scanned: number;
  files_skipped?: string[];
  summary: string;
  primary_model: string;
  scan_time_seconds: number;
  header_status?: any;
}

const scanHistory: ScanRecord[] = [];

// Lightweight in-memory rate limiter to prevent abuse on public scan/chat endpoints
const requestBuckets = new Map<string, { count: number; resetTime: number }>();
function rateLimit(limitPerMinute = 40) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const bucket = requestBuckets.get(ip) || { count: 0, resetTime: now + 60000 };

    if (now > bucket.resetTime) {
      bucket.count = 0;
      bucket.resetTime = now + 60000;
    }

    bucket.count += 1;
    requestBuckets.set(ip, bucket);

    if (bucket.count > limitPerMinute) {
      return res.status(429).json({
        error: 'Too many requests. Please slow down and try again shortly.',
        retry_after_seconds: Math.ceil((bucket.resetTime - now) / 1000),
      });
    }
    next();
  };
}

// Helper: SSRF IP validator preventing access to private, loopback, link-local, and cloud metadata IPs
function isPrivateOrReservedIp(ip: string): boolean {
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  if (ip.includes('.')) {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return true;
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8 RFC1918
    if (a === 127) return true; // 127.0.0.0/8 Loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-local / Cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 Shared CGNAT
    if (a >= 224) return true; // Multicast & Reserved
    return false;
  }

  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe80:')) return true; // Link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // Unique local
  return false;
}

// Validate URLs for SSRF safety
async function validateSafePublicUrl(rawUrl: string): Promise<{ valid: boolean; error?: string; normalizedUrl?: string }> {
  let parsed: URL;
  try {
    const candidate = rawUrl.startsWith('http://') || rawUrl.startsWith('https://') ? rawUrl : `https://${rawUrl}`;
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Malformed or invalid URL string.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS protocols are allowed.' };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname === '::1' ||
    hostname === '169.254.169.254' ||
    hostname === 'metadata.google.internal' ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local')
  ) {
    return { valid: false, error: 'SSRF Protection: Access to private, local, or cloud metadata network addresses is prohibited.' };
  }

  try {
    const lookupResults = await dns.promises.lookup(hostname, { all: true });
    for (const entry of lookupResults) {
      if (isPrivateOrReservedIp(entry.address)) {
        return {
          valid: false,
          error: `SSRF Protection: Hostname resolves to restricted private IP address (${entry.address}).`,
        };
      }
    }
  } catch (err: any) {
    return { valid: false, error: `Domain DNS resolution failed: ${err.message || 'Host unreachable'}` };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

// Static Security Rules
const STATIC_SECURITY_PATTERNS = [
  {
    id: "sqli-concat",
    title: "SQL Injection via Dynamic String Concatenation",
    severity: "critical",
    owasp: "A03:2021-Injection",
    regex: /(SELECT\s+.*FROM\s+.*WHERE\s+.*['"]\s*\+|cursor\.execute\s*\(\s*f["']|\.execute\s*\(\s*["'].*\%|\.query\s*\(\s*[`'"].*\$\{)/i,
    description: "User input is directly interpolated into raw SQL queries without parameterized binding.",
    attack_scenario: "An attacker can inject malicious SQL payloads (e.g., ' OR 1=1 --) to bypass authentication or extract sensitive tables.",
    fix: "Use parameterized queries or ORM query builders (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)))"
  },
  {
    id: "cmdi-subprocess",
    title: "Command Injection via Shell Execution",
    severity: "critical",
    owasp: "A03:2021-Injection",
    regex: /(subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|exec\s*\(.*req\.)/i,
    description: "System commands executed via shell interpreter with untrusted input.",
    attack_scenario: "Attacker injects shell metacharacters (; & | `) to execute arbitrary commands on the underlying host operating system.",
    fix: "Set shell=False and pass arguments as an array/list, or use safe APIs like subprocess.run(['echo', param], shell=False)."
  },
  {
    id: "secrets-hardcoded",
    title: "Hardcoded API Token / Secret Credentials",
    severity: "critical",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z-_]{35}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|(secret_key|api_key|password)\s*=\s*['"][a-zA-Z0-9_\-\.]{8,}['"])/i,
    description: "Private API secrets, service keys, or tokens committed directly to source code.",
    attack_scenario: "Anyone with access to the codebase or repository can impersonate the service and compromise infrastructure.",
    fix: "Extract credentials to environment variables (.env) or a cloud secret management vault."
  },
  {
    id: "insecure-deserialization",
    title: "Insecure Deserialization (pickle/yaml)",
    severity: "critical",
    owasp: "A08:2021-Software and Data Integrity Failures",
    regex: /(pickle\.loads\s*\(|_pickle\.loads\s*\(|yaml\.load\s*\([^,)]*\))/i,
    description: "Unpickling or loading untrusted serialized byte streams.",
    attack_scenario: "Attacker crafts malicious serialized objects (using __reduce__) resulting in immediate remote code execution (RCE).",
    fix: "Never deserialize untrusted payloads with pickle; utilize structured JSON or cryptography-signed payloads."
  },
  {
    id: "xss-inner-html",
    title: "Cross-Site Scripting (XSS) via Direct DOM Insertion",
    severity: "high",
    owasp: "A03:2021-Injection",
    regex: /(dangerouslySetInnerHTML\s*=|innerHTML\s*=|document\.write\s*\(|v-html\s*=)/i,
    description: "Unsanitized user content rendered directly into document HTML.",
    attack_scenario: "Attacker injects script tags (<script> or <img onerror>) to hijack session cookies or conduct phishing.",
    fix: "Sanitize user inputs with DOMPurify or use standard textContent rendering."
  },
  {
    id: "weak-crypto",
    title: "Use of Deprecated Weak Hash Algorithm",
    severity: "low",
    owasp: "A02:2021-Cryptographic Failures",
    regex: /(hashlib\.md5|hashlib\.sha1|crypto\.createHash\s*\(\s*['"](md5|sha1)['"]\))/i,
    description: "MD5 or SHA1 utilized for integrity or password storage.",
    attack_scenario: "Collisions and high-speed GPU cracking tables allow pre-image recovery.",
    fix: "Migrate to SHA-256/SHA-512 or Argon2id/bcrypt for password hashing."
  },
  {
    id: "eval-function",
    title: "Dynamic Arbitrary Code Evaluation (eval)",
    severity: "high",
    owasp: "A03:2021-Injection",
    regex: /(\beval\s*\(|\bexec\s*\(|\bnew\s+Function\s*\()/i,
    description: "Dynamic evaluation of code strings at runtime.",
    attack_scenario: "Arbitrary JavaScript or Python execution in the current process context.",
    fix: "Refactor dynamic evaluation to structured dispatch tables or JSON.parse."
  }
];

// Helper to query npm registry
async function checkNpmPackage(pkgName: string): Promise<boolean> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`, {
      headers: { 'User-Agent': 'VibeSec-Scanner/1.0' },
      signal: AbortSignal.timeout(4000)
    });
    return res.status === 200;
  } catch {
    return true; // Fallback to avoid false positives on network error
  }
}

// Helper to query PyPI
async function checkPyPiPackage(pkgName: string): Promise<boolean> {
  try {
    const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(pkgName)}/json`, {
      headers: { 'User-Agent': 'VibeSec-Scanner/1.0' },
      signal: AbortSignal.timeout(4000)
    });
    return res.status === 200;
  } catch {
    return true;
  }
}

// Extract imports from code
function extractCodeImports(code: string, language: string): string[] {
  const pkgs = new Set<string>();
  const isPython = language.toLowerCase().includes('py');

  if (isPython) {
    const pyImportRegex = /^\s*(?:import|from)\s+([a-zA-Z0-9_]+)/gm;
    let match;
    const stdlib = new Set([
      'os', 'sys', 're', 'json', 'time', 'datetime', 'math', 'random', 'subprocess',
      'shutil', 'logging', 'argparse', 'hashlib', 'sqlite3', 'urllib', 'http', 'pickle',
      'typing', 'collections', 'itertools', 'functools', 'pathlib', 'tempfile', 'copy'
    ]);
    while ((match = pyImportRegex.exec(code)) !== null) {
      const name = match[1];
      if (!stdlib.has(name) && !name.startsWith('.')) {
        pkgs.add(name);
      }
    }
  } else {
    // JS / TS
    const esmRegex = /(?:import\s+(?:[\w\s{},*]+from\s+)?|import\s*\(\s*)['"]([^'"\n]+)['"]/g;
    const cjsRegex = /require\s*\(\s*['"]([^'"\n]+)['"]\s*\)/g;
    const nodeBuiltins = new Set([
      'fs', 'path', 'http', 'https', 'os', 'crypto', 'util', 'stream', 'events',
      'buffer', 'child_process', 'cluster', 'dns', 'net', 'url', 'zlib', 'readline'
    ]);

    for (const r of [esmRegex, cjsRegex]) {
      let m;
      while ((m = r.exec(code)) !== null) {
        const raw = m[1].replace('node:', '').trim();
        if (raw.startsWith('.') || raw.startsWith('/')) continue;
        const root = raw.startsWith('@') ? raw.split('/').slice(0, 2).join('/') : raw.split('/')[0];
        if (!nodeBuiltins.has(root) && !root.startsWith('@types/')) {
          pkgs.add(root);
        }
      }
    }
  }

  return Array.from(pkgs);
}

// AI deep analysis agent
async function analyzeWithAI(codeSnippet: string, language: string, staticFindings: any[]) {
  if (!process.env.GEMINI_API_KEY) {
    return { model: 'VibeSec Heuristics Engine', findings: staticFindings };
  }

  try {
    const ai = new GoogleGenAI();
    const prompt = `You are VibeSec, an elite cybersecurity auditor specializing in vulnerabilities in AI-generated code.
Audit the following code snippet (${language}).
Existing static analysis triggers: ${JSON.stringify(staticFindings.map(f => f.title))}

Code to audit:
\`\`\`${language}
${codeSnippet.slice(0, 3000)}
\`\`\`

Respond ONLY with a JSON object in this exact schema:
{
  "summary": "one sentence audit verdict",
  "vulnerabilities": [
    {
      "title": "short title",
      "severity": "critical" | "high" | "medium" | "low",
      "owasp": "OWASP code and name (e.g. A03:2021-Injection)",
      "description": "concrete technical vulnerability description",
      "attack_scenario": "how an adversary would exploit this flaw",
      "line_hint": 1,
      "confidence": "high" | "medium",
      "fix": "exact replacement code or precise remediation instruction"
    }
  ]
}`;

    const response = await ai.models.generateContent({
      model: GEMINI_MODEL,
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      }
    });

    const parsed = JSON.parse(response.text || '{}');
    if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
      return { model: `Gemini (${GEMINI_MODEL})`, findings: parsed.vulnerabilities, summary: parsed.summary };
    }
  } catch (err) {
    console.warn("AI generation failed, relying on deterministic rules:", err);
  }

  return { model: 'VibeSec Static Heuristics', findings: staticFindings };
}

// Render Liveness check endpoint
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', service: 'vibesec-express-api' });
});

// 1. HEALTH CHECK — proxy the live FastAPI health status.
app.get('/api/health', async (_req, res) => {
  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/health`, {
      method: 'GET',
      headers: getInternalHeaders({ 'Accept': 'application/json' }),
      signal: AbortSignal.timeout(12000),
    });
    const body = await backendRes.text();
    res.status(backendRes.status);
    res.setHeader('Content-Type', backendRes.headers.get('content-type') || 'application/json');
    return res.send(body);
  } catch (err: any) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    return res.status(timedOut ? 504 : 503).json({
      status: 'degraded',
      detail: timedOut
        ? 'FastAPI health check timed out.'
        : `FastAPI is unavailable at ${FASTAPI_URL}. Confirm it is running.`,
    });
  }
});

// 2. SCAN CODE — Authoritative scan via FastAPI
app.post('/api/scan/code', rateLimit(60), async (req, res) => {
  const { code, language = 'python', filename = 'snippet' } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Code content must be provided' });
  }

  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/scan/code`, {
      method: 'POST',
      headers: getInternalHeaders(req, {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      }),
      body: JSON.stringify({ code, language, filename }),
      signal: AbortSignal.timeout(60000),
    });

    const forwardSid = backendRes.headers.get('x-session-id');
    const forwardTok = backendRes.headers.get('x-session-token');
    if (forwardSid) res.setHeader('X-Session-ID', forwardSid);
    if (forwardTok) res.setHeader('X-Session-Token', forwardTok);

    if (backendRes.ok) {
      const data = await backendRes.json();
      scanHistory.unshift(data);
      return res.json(data);
    } else {
      const errJson = await backendRes.json().catch(() => null);
      return res.status(backendRes.status).json(errJson || { error: `Code scan failed with status ${backendRes.status}` });
    }
  } catch (err: any) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    return res.status(timedOut ? 504 : 503).json({
      error: timedOut ? 'Code scan timed out.' : `VibeSec FastAPI backend is unavailable at ${FASTAPI_URL}. Ensure FastAPI is operational.`,
      detail: timedOut ? 'Request exceeded the backend processing deadline.' : 'FastAPI scanner service is unreachable.',
    });
  }
});

// 3. SCAN URL — Authoritative scan via FastAPI
app.post('/api/scan/url', rateLimit(30), async (req, res) => {
  let { url } = req.body;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL is required.' });

  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/scan/url`, {
      method: 'POST',
      headers: getInternalHeaders(req, {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      }),
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(45000),
    });

    const forwardSid = backendRes.headers.get('x-session-id');
    const forwardTok = backendRes.headers.get('x-session-token');
    if (forwardSid) res.setHeader('X-Session-ID', forwardSid);
    if (forwardTok) res.setHeader('X-Session-Token', forwardTok);

    if (backendRes.ok) {
      const data = await backendRes.json();
      scanHistory.unshift(data);
      return res.json(data);
    } else {
      const errJson = await backendRes.json().catch(() => null);
      return res.status(backendRes.status).json(errJson || { error: `URL scan failed with status ${backendRes.status}` });
    }
  } catch (err: any) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    return res.status(timedOut ? 504 : 503).json({
      error: timedOut ? 'URL scan timed out.' : `VibeSec FastAPI backend is unavailable at ${FASTAPI_URL}. Ensure FastAPI is operational.`,
      detail: timedOut ? 'Request exceeded the backend processing deadline.' : 'FastAPI scanner service is unreachable.',
    });
  }
});

// GitHub Headers helper attaching optional GITHUB_TOKEN and GitHub API standards
function getGitHubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': 'VibeSec-GitHub-Scanner/1.0 (NIELIT Gorakhpur Major Project)',
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const token = (process.env.GITHUB_TOKEN || '').trim();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function extractRateLimitHeaders(headers: Headers): Record<string, string> {
  const info: Record<string, string> = {};
  for (const key of ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'retry-after']) {
    const val = headers.get(key);
    if (val !== null) info[key] = val;
  }
  return info;
}

function isEnvTemplateFilename(path: string): boolean {
  if (!path) return false;
  const normalized = path.replace(/\\/g, '/').toLowerCase();
  const filename = normalized.split('/').pop() || '';
  if (['.env.example', '.env.sample', '.env.template', '.env.dist', '.env.defaults', '.env.sample.local', '.env.test'].includes(filename)) {
    return true;
  }
  if (/\.env\.(example|sample|template|dist|defaults)$/i.test(filename)) {
    return true;
  }
  if (/^(example|sample|template)\.env$/i.test(filename)) {
    return true;
  }
  if (filename.endsWith('.example') || filename.endsWith('.sample') || filename.endsWith('.template')) {
    return true;
  }
  return false;
}

function isCommittedEnvFilename(path: string): boolean {
  if (!path) return false;
  const normalized = path.replace(/\\/g, '/').toLowerCase();
  const filename = normalized.split('/').pop() || '';
  if (isEnvTemplateFilename(filename)) return false;
  if (filename === '.env') return true;
  if (filename.startsWith('.env.')) return true;
  return false;
}

const PLACEHOLDER_SUBSTRINGS = [
  'your-', 'your_', 'your ', '<your',
  'change_me', 'changeme', 'change-me', 'change_this',
  'replace_me', 'replaceme', 'replace-me', 'replace_this',
  'insert_here', 'insert_', 'insert-', 'enter-your', 'enter_your',
  'placeholder', 'example', 'sample', 'dummy', 'fake', 'todo', 'tbd',
  'xxx', 'xxxx', 'secret_here', 'key_here', 'token_here', 'password_here',
  'your-random-', 'your-strong-', 'your-secret-', 'your_secret_',
  'my-secret', 'my_secret', 'some-secret', 'some_secret',
  'postgres://user:password@', 'mongodb://localhost', 'localhost', '127.0.0.1',
  'http://', 'https://', 'not-a-real', 'test-token',
];

function isPlaceholderValue(val: string): boolean {
  const cleaned = val.trim().replace(/^['"]|['"]$/g, '').trim();
  if (!cleaned) return true;
  if (/^<.*>$/.test(cleaned) || /^\[.*\]$/.test(cleaned) || /^\{.*\}$/.test(cleaned) || /^\*.*\*$/.test(cleaned)) return true;
  if (cleaned.startsWith('(') && cleaned.endsWith(')')) return true;

  const lower = cleaned.toLowerCase();
  for (const sub of PLACEHOLDER_SUBSTRINGS) {
    if (lower.includes(sub)) return true;
  }
  if (['true', 'false', 'null', 'none', 'undefined', 'dev', 'prod', 'test', 'local', 'development', 'production', 'default'].includes(lower)) {
    return true;
  }
  if (/^\d+$/.test(lower)) return true;
  return false;
}

const SENSITIVE_KEY_REGEX = /SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE_KEY|AUTH|CREDENTIAL|API_KEY|ACCESS_KEY|DATABASE_URL|MONGODB_URI|REDIS_URL|DB_PASS|MASTER_KEY|ENCRYPTION_KEY|PROXY_TOKEN/i;

const HIGH_CONFIDENCE_SECRET_PATTERNS: [RegExp, string][] = [
  [/sk-[a-zA-Z0-9]{20,}/, 'OpenAI / Stripe Secret Key'],
  [/AIza[0-9A-Za-z-_]{35}/, 'Google Cloud API Key'],
  [/(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})/, 'GitHub Personal Access Token'],
  [/AKIA[0-9A-Z]{16}/, 'AWS Access Key ID'],
  [/sq0atp-[0-9A-Za-z\-_]{22}/, 'Square Access Token'],
  [/eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]+/, 'Exposed JWT Token'],
  [/xox[baprs]-[0-9a-zA-Z]{10,48}/, 'Slack Token'],
  [/-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----/, 'Private Cryptographic Key'],
];

function inspectEnvFileContent(content: string, path: string): any[] {
  const findings: any[] = [];
  const lines = content.split('\n');
  const isTemplate = isEnvTemplateFilename(path);
  const isRuntimeEnv = isCommittedEnvFilename(path);

  const realSecretsFound: { lineNum: number; lineStr: string; keyName: string; secretType: string }[] = [];

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNum = idx + 1;
    const stripped = lines[idx].trim();
    if (!stripped || stripped.startsWith('#')) continue;

    let matchedToken = false;
    for (const [pat, desc] of HIGH_CONFIDENCE_SECRET_PATTERNS) {
      const m = stripped.match(pat);
      if (m && !isPlaceholderValue(m[0])) {
        realSecretsFound.push({ lineNum, lineStr: stripped, keyName: 'TOKEN', secretType: desc });
        matchedToken = true;
        break;
      }
    }
    if (matchedToken) continue;

    if (stripped.includes('=')) {
      const eqIdx = stripped.indexOf('=');
      const key = stripped.slice(0, eqIdx).trim();
      const val = stripped.slice(eqIdx + 1).trim();

      if (SENSITIVE_KEY_REGEX.test(key) && !isPlaceholderValue(val)) {
        realSecretsFound.push({ lineNum, lineStr: stripped, keyName: key, secretType: 'Sensitive Credential' });
      }
    }
  }

  if (isTemplate) {
    for (const sec of realSecretsFound) {
      findings.push({
        title: `Exposed Credential in Environment Template: ${sec.keyName}`,
        severity: 'critical',
        owasp: 'A07:2021-Identification and Authentication Failures',
        description: `Real credential or private key was found committed in environment template '${path}' (line ${sec.lineNum}).`,
        attack_scenario: 'Developers inadvertently committed genuine API tokens or passwords into documentation templates.',
        file: path,
        line_hint: sec.lineNum,
        code_snippet: sec.lineStr,
        confidence: 'high',
        fix: `Replace the real value of ${sec.keyName} with a safe placeholder (e.g. YOUR_${sec.keyName}) and revoke the exposed credential.`,
      });
    }
    return findings;
  }

  if (isRuntimeEnv || path.toLowerCase().endsWith('.env')) {
    if (realSecretsFound.length > 0) {
      const first = realSecretsFound[0];
      const evidence = realSecretsFound.slice(0, 5).map((s) => `Line ${s.lineNum}: ${s.lineStr}`).join('\n');
      findings.push({
        title: 'Committed Sensitive Environment File (.env)',
        severity: 'critical',
        owasp: 'A05:2021-Security Misconfiguration',
        description: `Active environment credentials file '${path}' containing live credentials was committed to source control.`,
        attack_scenario: 'Attackers scraping repository history can extract database credentials, production API tokens, and secret keys.',
        file: path,
        line_hint: first.lineNum,
        code_snippet: evidence,
        confidence: 'high',
        fix: 'Remove file from repository history with git-filter-repo and append .env to .gitignore.',
      });
    }
  }

  return findings;
}

const githubScanCache = new Map<string, { timestamp: number; record: ScanRecord }>();
const GITHUB_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// 4. SCAN GITHUB REPOSITORY (with command injection defense, caching, rate limit headers & archive fallback)
app.post('/api/scan/github', rateLimit(20), async (req, res) => {
  const startTime = Date.now();
  const { repo_url } = req.body;
  if (!repo_url || typeof repo_url !== 'string' || !repo_url.includes('github.com')) {
    return res.status(400).json({ error: 'Valid GitHub repository URL required.' });
  }

  const match = repo_url.trim().match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([a-zA-Z0-9_\-\.]+)\/([a-zA-Z0-9_\-\.]+?)(?:\.git)?\/?$/);
  if (!match) {
    return res.status(400).json({ error: 'Could not parse owner/repo from URL. Must be in format https://github.com/owner/repo' });
  }

  const owner = match[1];
  const repo = match[2].replace(/\.git$/, '');

  // Validate owner and repo identifiers against command injection / path traversal
  const validIdent = /^[a-zA-Z0-9_\-\.]+$/;
  if (!validIdent.test(owner) || !validIdent.test(repo) || owner.includes('..') || repo.includes('..')) {
    return res.status(400).json({ error: 'Invalid characters in GitHub owner or repository name.' });
  }

  const cacheKey = `${owner.toLowerCase()}/${repo.toLowerCase()}`;
  const cached = githubScanCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < GITHUB_CACHE_TTL_MS) {
    const resolvedSession = resolveSessionForScan(req, res);
    const clone: ScanRecord = {
      ...cached.record,
      scan_id: `vibesec-${Date.now()}`,
      created_at: new Date().toISOString(),
      session_id: resolvedSession.sessionId,
      session_token: resolvedSession.sessionToken,
    };
    scanHistory.unshift(clone);
    return res.json(clone);
  }

  // 1. Try delegating to FastAPI backend if running
  try {
    const sessionId = getSessionIdFromReq(req);
    const backendRes = await fetch(`${FASTAPI_URL}/api/scan/github`, {
      method: 'POST',
      headers: getInternalHeaders(req, {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(sessionId ? { 'X-Session-ID': sessionId } : {}),
      }),
      body: JSON.stringify({ repo_url }),
      signal: AbortSignal.timeout(50000),
    });

    if (backendRes.ok) {
      const data = await backendRes.json();
      if (data && typeof data === 'object' && Number(data.files_scanned) > 0) {
        githubScanCache.set(cacheKey, { timestamp: Date.now(), record: data });
        scanHistory.unshift(data);
        return res.json(data);
      }
    } else if (backendRes.status === 404 || backendRes.status === 403 || backendRes.status === 400) {
      const errJson = await backendRes.json().catch(() => null);
      return res.status(backendRes.status).json(errJson || { error: `GitHub scan failed with status ${backendRes.status}` });
    }
  } catch {
    // Backend unavailable or timed out; proceed to Express standalone scanner
  }

  // 2. Express standalone scanner with direct public archive fallback
  const vulns: any[] = [];
  const filesScanned: string[] = [];
  const filesSkipped: string[] = [];
  let needsArchiveDownload = false;
  let defaultBranch = 'main';
  let scanMethod = 'rest_api';

  try {
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: getGitHubHeaders(),
      signal: AbortSignal.timeout(10000),
    });

    const rlHeaders = extractRateLimitHeaders(repoRes.headers);

    if (repoRes.status === 404) {
      return res.status(404).json({
        error: `GitHub repository '${owner}/${repo}' was not found. Verify the owner and repository name, and ensure the repository is public.`,
      });
    }

    const isRateLimited =
      repoRes.status === 429 ||
      (repoRes.status === 403 && (rlHeaders['x-ratelimit-remaining'] === '0' || (await repoRes.clone().text()).toLowerCase().includes('rate limit')));

    if (isRateLimited) {
      console.warn(`[GitHubScanner] Rate limit reached for ${owner}/${repo} (status ${repoRes.status}). Falling back to archive download.`);
      needsArchiveDownload = true;
    } else if (repoRes.status === 401 || repoRes.status === 403) {
      return res.status(403).json({
        error: `Access to GitHub repository '${owner}/${repo}' is forbidden. Private repositories cannot be audited without authentication.`,
      });
    } else if (!repoRes.ok) {
      console.warn(`[GitHubScanner] GitHub API returned status ${repoRes.status}. Falling back to archive download.`);
      needsArchiveDownload = true;
    } else {
      const repoData = await repoRes.json();
      defaultBranch = repoData.default_branch || 'main';

      // Fetch git tree
      const treeRes = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`,
        {
          headers: getGitHubHeaders(),
          signal: AbortSignal.timeout(15000),
        }
      );

      const treeRl = extractRateLimitHeaders(treeRes.headers);
      const treeRateLimited =
        treeRes.status === 429 ||
        (treeRes.status === 403 && (treeRl['x-ratelimit-remaining'] === '0' || (await treeRes.clone().text()).toLowerCase().includes('rate limit')));

      if (treeRateLimited || !treeRes.ok) {
        console.warn(`[GitHubScanner] Tree API failed with status ${treeRes.status}. Falling back to archive download.`);
        needsArchiveDownload = true;
      } else {
        const treeData = await treeRes.json();
        const treeItems = treeData.tree || [];
        const scannableExtensions = new Set(['.py', '.js', '.ts', '.tsx', '.jsx', '.php', '.java', '.go', '.json', '.env']);
        const candidates: string[] = [];

        for (const item of treeItems) {
          if (item.type !== 'blob') continue;
          const pathStr = item.path as string;
          const lower = pathStr.toLowerCase();

          // Vendor skip
          if (
            lower.includes('node_modules/') ||
            lower.includes('.git/') ||
            lower.includes('__pycache__/') ||
            lower.includes('.venv/') ||
            lower.includes('venv/') ||
            lower.includes('dist/') ||
            lower.includes('build/') ||
            lower.endsWith('.min.js')
          ) {
            filesSkipped.push(pathStr);
            continue;
          }

          const filenameOnly = pathStr.split('/').pop() || '';
          const isEnvFile = isCommittedEnvFilename(pathStr) || isEnvTemplateFilename(pathStr) || filenameOnly.startsWith('.env');

          const dotIdx = pathStr.lastIndexOf('.');
          const ext = dotIdx !== -1 ? pathStr.slice(dotIdx).toLowerCase() : '';
          if (isEnvFile || scannableExtensions.has(ext)) {
            candidates.push(pathStr);
          } else {
            filesSkipped.push(pathStr);
          }
        }

        // Scan candidate source files
        for (const filePath of candidates.slice(0, 15)) {
          try {
            const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${filePath}`;
            const rawRes = await fetch(rawUrl, {
              headers: getGitHubHeaders(),
              signal: AbortSignal.timeout(6000),
            });
            if (rawRes.ok) {
              filesScanned.push(filePath);
              const content = await rawRes.text();
              const isEnv = isCommittedEnvFilename(filePath) || isEnvTemplateFilename(filePath) || filePath.split('/').pop()?.startsWith('.env');
              if (isEnv) {
                const envFindings = inspectEnvFileContent(content, filePath);
                vulns.push(...envFindings);
              } else {
                for (const pattern of STATIC_SECURITY_PATTERNS) {
                  if (pattern.regex.test(content)) {
                    vulns.push({
                      title: `${pattern.title}`,
                      severity: pattern.severity,
                      owasp: pattern.owasp,
                      description: pattern.description,
                      attack_scenario: pattern.attack_scenario,
                      file: filePath,
                      line_hint: 1,
                      confidence: 'high',
                      fix: pattern.fix,
                    });
                  }
                }
              }
            }
          } catch {}
        }
      }
    }
  } catch (err: any) {
    console.warn(`[GitHubScanner] REST API error: ${err.message}. Triggering archive download.`);
    needsArchiveDownload = true;
  }

  // 3. Fallback: Download public archive zip directly
  if (needsArchiveDownload) {
    scanMethod = 'archive_download';
    const archiveUrls = [
      `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/${defaultBranch}`,
      `https://github.com/${owner}/${repo}/archive/refs/heads/${defaultBranch}.zip`,
      `https://codeload.github.com/${owner}/${repo}/zip/HEAD`,
      `https://github.com/${owner}/${repo}/archive/HEAD.zip`,
    ];

    let zipBuffer: Buffer | null = null;
    let archiveStatus = 0;

    for (const url of archiveUrls) {
      try {
        const resp = await fetch(url, {
          headers: { 'User-Agent': 'VibeSec-GitHub-Scanner/1.0 (NIELIT Gorakhpur Major Project)' },
          signal: AbortSignal.timeout(20000),
        });
        archiveStatus = resp.status;
        if (resp.ok) {
          const ab = await resp.arrayBuffer();
          if (ab.byteLength > 25 * 1024 * 1024) {
            return res.status(413).json({ error: 'Repository archive exceeds the 25MB safety download limit.' });
          }
          zipBuffer = Buffer.from(ab);
          break;
        } else if (resp.status === 404) {
          continue;
        } else if (resp.status === 401 || resp.status === 403) {
          return res.status(403).json({ error: `Repository '${owner}/${repo}' is private or inaccessible.` });
        }
      } catch {}
    }

    if (!zipBuffer) {
      if (archiveStatus === 404) {
        return res.status(404).json({ error: `GitHub repository '${owner}/${repo}' was not found.` });
      }
      return res.status(502).json({ error: `Unable to access repository '${owner}/${repo}' via REST API or archive download.` });
    }

    try {
      const zip = await JSZip.loadAsync(zipBuffer);
      const scannableExtensions = new Set(['.py', '.js', '.ts', '.tsx', '.jsx', '.php', '.java', '.go', '.json', '.env']);
      const candidates: { path: string; file: any }[] = [];
      let totalUncompressed = 0;

      for (const [entryPath, zipEntry] of Object.entries(zip.files)) {
        if (zipEntry.dir) continue;

        // Strip repo prefix
        const parts = entryPath.split('/');
        const relPath = parts.slice(1).join('/');
        const normalized = relPath.replace(/\\/g, '/');

        // Zip-Slip defense
        if (normalized.includes('../') || normalized.startsWith('/') || normalized.startsWith('../')) {
          filesSkipped.push(`${relPath} (skipped: illegal path)`);
          continue;
        }

        if (candidates.length + filesSkipped.length >= 500) {
          filesSkipped.push('Remaining archive files (skipped: exceeded 500 files ceiling)');
          break;
        }

        const lower = normalized.toLowerCase();
        if (
          lower.includes('node_modules/') ||
          lower.includes('.git/') ||
          lower.includes('__pycache__/') ||
          lower.includes('.venv/') ||
          lower.includes('venv/') ||
          lower.includes('dist/') ||
          lower.includes('build/') ||
          lower.endsWith('.min.js')
        ) {
          filesSkipped.push(normalized);
          continue;
        }

        const filenameOnly = normalized.split('/').pop() || '';
        const isEnvFile = isCommittedEnvFilename(normalized) || isEnvTemplateFilename(normalized) || filenameOnly.startsWith('.env');

        const dotIdx = normalized.lastIndexOf('.');
        const ext = dotIdx !== -1 ? normalized.slice(dotIdx).toLowerCase() : '';
        if (isEnvFile || scannableExtensions.has(ext)) {
          candidates.push({ path: normalized, file: zipEntry });
        } else {
          filesSkipped.push(normalized);
        }
      }

      // Scan up to 15 files from archive
      for (const item of candidates.slice(0, 15)) {
        try {
          const content = await item.file.async('text');
          totalUncompressed += content.length;
          if (totalUncompressed > 50 * 1024 * 1024) break;

          filesScanned.push(item.path);
          const isEnv = isCommittedEnvFilename(item.path) || isEnvTemplateFilename(item.path) || item.path.split('/').pop()?.startsWith('.env');
          if (isEnv) {
            const envFindings = inspectEnvFileContent(content, item.path);
            vulns.push(...envFindings);
          } else {
            for (const pattern of STATIC_SECURITY_PATTERNS) {
              if (pattern.regex.test(content)) {
                vulns.push({
                  title: `${pattern.title}`,
                  severity: pattern.severity,
                  owasp: pattern.owasp,
                  description: pattern.description,
                  attack_scenario: pattern.attack_scenario,
                  file: item.path,
                  line_hint: 1,
                  confidence: 'high',
                  fix: pattern.fix,
                });
              }
            }
          }
        } catch {}
      }
    } catch (err: any) {
      return res.status(502).json({ error: `Failed to unpack repository archive: ${err.message}` });
    }
  }

  // Never report API issues as vulnerabilities, and ensure files were analyzed
  if (filesScanned.length === 0) {
    return res.status(422).json({
      error: `No scannable source code files could be downloaded from repository '${owner}/${repo}'.`,
    });
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
  if (vulns.length === 0) {
    counts.safe = 1;
  } else {
    for (const v of vulns) {
      const sev = (v.severity || 'medium').toLowerCase() as keyof typeof counts;
      if (counts[sev] !== undefined) counts[sev]++;
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  const resolvedSession = resolveSessionForScan(req, res);
  const scanRecord: ScanRecord = {
    scan_id: `vibesec-${Date.now()}`,
    created_at: new Date().toISOString(),
    session_id: resolvedSession.sessionId,
    session_token: resolvedSession.sessionToken,
    input_type: 'github',
    target: repo_url,
    vulnerabilities: vulns,
    severity_counts: counts,
    files_scanned: filesScanned.length,
    files_skipped: filesSkipped.slice(0, 20),
    summary: `Repository audit of ${owner}/${repo} (${defaultBranch}) via ${scanMethod} completed in ${duration}s. Scanned ${filesScanned.length} files (${filesSkipped.length} vendor files skipped). Identified ${vulns.length} vulnerabilities.`,
    primary_model: 'VibeSec GitHub Auditor',
    scan_time_seconds: parseFloat(duration),
  };

  githubScanCache.set(cacheKey, { timestamp: Date.now(), record: scanRecord });
  scanHistory.unshift(scanRecord);
  return res.json(scanRecord);
});

// 5. SCAN UPLOAD (Multipart streaming to FastAPI + JSON base64 fallback with 100MB upload & 250MB/500 files unzip limits)
app.post('/api/scan/upload', rateLimit(25), async (req, res) => {
  const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB
  const MAX_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024; // 250 MB
  const MAX_ZIP_FILES = 500; // 500 files

  // 1. Multipart Form Upload (Browser FormData streaming directly to FastAPI)
  if (req.is('multipart/form-data')) {
    const contentLength = parseInt((req.headers['content-length'] as string) || '0', 10);
    if (contentLength > MAX_UPLOAD_BYTES) {
      return res.status(413).json({
        error: `Uploaded file exceeds the maximum allowed limit of 100MB (${(contentLength / (1024 * 1024)).toFixed(1)}MB).`,
        detail: `Uploaded file exceeds the maximum allowed limit of 100MB.`,
      });
    }

    const headers = getInternalHeaders(req, {
      'content-type': req.headers['content-type']!,
    });

    try {
      const bodyStream = Readable.toWeb(req);
      const backendRes = await fetch(`${FASTAPI_URL}/api/scan/upload`, {
        method: 'POST',
        headers,
        body: bodyStream,
        duplex: 'half',
        signal: AbortSignal.timeout(600000), // 10 minutes timeout for 100MB upload & analysis
      } as any);

      const respData = await backendRes.json().catch(() => null);
      if (!backendRes.ok) {
        return res.status(backendRes.status).json(respData || { error: 'Scan upload failed in backend.' });
      }
      if (respData) {
        if (respData.session_id) {
          res.setHeader('X-Session-ID', respData.session_id);
        }
        if (respData.session_token) {
          res.setHeader('X-Session-Token', respData.session_token);
        }
        scanHistory.unshift(respData);
      }
      return res.status(backendRes.status).json(respData);
    } catch (err: any) {
      const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
      return res.status(timedOut ? 504 : 503).json({
        error: timedOut ? 'Upload processing timed out waiting for backend scanner.' : `Backend error: ${err.message}`,
        detail: timedOut ? 'Upload processing timed out waiting for backend scanner.' : `Backend error: ${err.message}`,
      });
    }
  }

  // 2. JSON Base64 or Text File Upload Handling
  const startTime = Date.now();
  const { filename = 'archive.zip', content = '', is_zip = false } = req.body || {};

  const vulns: any[] = [];
  const filesScanned: string[] = [];
  const filesSkipped: string[] = [];
  let totalUncompressedBytes = 0;

  try {
    if (is_zip && content) {
      const zipBuffer = Buffer.from(content, 'base64');
      if (zipBuffer.length > MAX_UPLOAD_BYTES) {
        return res.status(413).json({
          error: `Uploaded file exceeds the maximum allowed limit of 100MB (${(zipBuffer.length / (1024 * 1024)).toFixed(1)}MB).`,
          detail: `Uploaded file exceeds the maximum allowed limit of 100MB.`,
        });
      }

      const zip = await JSZip.loadAsync(zipBuffer);

      for (const [relativePath, zipEntry] of Object.entries(zip.files)) {
        if (zipEntry.dir) continue;

        // Zip-Slip Protection: Reject traversal characters and absolute paths
        const normalized = relativePath.replace(/\\/g, '/');
        if (
          normalized.includes('../') ||
          normalized.startsWith('/') ||
          normalized.startsWith('../') ||
          /^[a-zA-Z]:/.test(normalized)
        ) {
          filesSkipped.push(`${relativePath} (skipped: illegal path)`);
          continue;
        }

        if (filesScanned.length >= MAX_ZIP_FILES) {
          filesSkipped.push(`Remaining archive files (skipped: max file limit of ${MAX_ZIP_FILES} reached)`);
          break;
        }

        const lower = normalized.toLowerCase();

        // STRICT SKIP
        if (
          lower.includes('node_modules/') ||
          lower.includes('.git/') ||
          lower.includes('__pycache__/') ||
          lower.includes('dist/') ||
          lower.includes('build/') ||
          lower.endsWith('.min.js')
        ) {
          filesSkipped.push(relativePath);
          continue;
        }

        const text = await zipEntry.async('text');
        totalUncompressedBytes += text.length;

        // Zip-Bomb Protection: Stop if uncompressed text exceeds limit (250MB or 500 files)
        if (totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
          vulns.push({
            title: 'Decompression Resource Limit Reached (Zip Bomb Protection)',
            severity: 'high',
            owasp: 'A05:2021-Security Misconfiguration',
            description: `Archive exceeds safety ceiling of ${MAX_TOTAL_UNCOMPRESSED_BYTES / (1024 * 1024)}MB uncompressed text. Scanning halted on remainder.`,
            attack_scenario: 'Denial of service through maliciously crafted nested or oversized compressed payload.',
            file: filename,
            line_hint: 1,
            confidence: 'high',
            fix: `Keep archives under ${MAX_TOTAL_UNCOMPRESSED_BYTES / (1024 * 1024)}MB total uncompressed source code and under ${MAX_ZIP_FILES} files.`,
          });
          break;
        }

        filesScanned.push(relativePath);

        for (const pattern of STATIC_SECURITY_PATTERNS) {
          if (pattern.regex.test(text)) {
            vulns.push({
              title: pattern.title,
              severity: pattern.severity,
              owasp: pattern.owasp,
              description: pattern.description,
              attack_scenario: pattern.attack_scenario,
              file: relativePath,
              line_hint: 1,
              confidence: 'high',
              fix: pattern.fix,
            });
          }
        }
      }
    } else {
      // Single file text
      const contentBytes = Buffer.byteLength(typeof content === 'string' ? content : '', 'utf8');
      if (contentBytes > MAX_UPLOAD_BYTES) {
        return res.status(413).json({
          error: `Uploaded file exceeds the maximum allowed limit of 100MB (${(contentBytes / (1024 * 1024)).toFixed(1)}MB).`,
          detail: `Uploaded file exceeds the maximum allowed limit of 100MB.`,
        });
      }

      filesScanned.push(filename);
      const safeContent = typeof content === 'string' ? content.slice(0, 500000) : '';
      for (const pattern of STATIC_SECURITY_PATTERNS) {
        if (pattern.regex.test(safeContent)) {
          vulns.push({
            title: pattern.title,
            severity: pattern.severity,
            owasp: pattern.owasp,
            description: pattern.description,
            attack_scenario: pattern.attack_scenario,
            file: filename,
            line_hint: 1,
            confidence: 'high',
            fix: pattern.fix,
          });
        }
      }
    }
  } catch (err: any) {
    vulns.push({
      title: 'Archive Unpack Error',
      severity: 'medium',
      owasp: 'A05:2021-Security Misconfiguration',
      description: err?.message || 'Failed to parse uploaded archive.',
      file: filename,
      fix: 'Verify file is a valid standard ZIP archive.',
    });
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
  if (vulns.length === 0) {
    counts.safe = 1;
  } else {
    for (const v of vulns) {
      const sev = (v.severity || 'medium').toLowerCase() as keyof typeof counts;
      if (counts[sev] !== undefined) counts[sev]++;
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  const resolvedSession = resolveSessionForScan(req, res);
  const scanRecord: ScanRecord = {
    scan_id: `vibesec-${Date.now()}`,
    created_at: new Date().toISOString(),
    session_id: resolvedSession.sessionId,
    session_token: resolvedSession.sessionToken,
    input_type: 'upload',
    filename,
    vulnerabilities: vulns,
    severity_counts: counts,
    files_scanned: filesScanned.length,
    files_skipped: filesSkipped.slice(0, 20),
    summary: `Archive scan of ${filename} finished in ${duration}s. Audited ${filesScanned.length} files (${filesSkipped.length} vendor files skipped).`,
    primary_model: 'VibeSec File Inspector',
    scan_time_seconds: parseFloat(duration),
  };

  scanHistory.unshift(scanRecord);
  res.json(scanRecord);
});

// 6. SESSION & HISTORY ENDPOINTS (Isolated per user/session with cryptographic token verification)
app.get('/api/session', (req, res) => {
  const authSid = getAuthenticatedSession(req);
  if (authSid) {
    const token = generateSessionToken(authSid);
    res.setHeader('X-Session-ID', authSid);
    res.setHeader('X-Session-Token', token);
    return res.json({ session_id: authSid, session_token: token, authenticated: true });
  }

  const newSid = 'vs_' + crypto.randomBytes(16).toString('hex');
  const newToken = generateSessionToken(newSid);
  res.setHeader('X-Session-ID', newSid);
  res.setHeader('X-Session-Token', newToken);
  return res.json({ session_id: newSid, session_token: newToken, authenticated: true });
});

app.get('/api/history', async (req, res) => {
  let clientSid = ((req.headers['x-session-id'] as string) || (req.query.session_id as string) || '').trim();
  let clientToken = ((req.headers['x-session-token'] as string) || (req.headers['x-session-signature'] as string) || (req.query.session_token as string) || '').trim();

  const authHeader = (req.headers['authorization'] as string) || '';
  if (authHeader.startsWith('Session ')) {
    const tokenPart = authHeader.substring(8).trim();
    if (!clientToken) clientToken = tokenPart;
    if (!clientSid && tokenPart.includes('.')) clientSid = tokenPart.split('.')[0];
  }

  // Reject client-supplied session ID without valid session authentication token
  if (clientSid && !clientToken) {
    return res.status(401).json({
      error: 'Unauthorized: Client-supplied X-Session-ID cannot be used without a valid X-Session-Token.',
      detail: 'Unauthorized: Client-supplied X-Session-ID cannot be used without a valid X-Session-Token.',
    });
  }

  // 1. First attempt to fetch from authoritative FastAPI backend
  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/history`, {
      method: 'GET',
      headers: getInternalHeaders(req, {
        'Accept': 'application/json',
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (backendRes.ok) {
      const data = await backendRes.json();
      return res.json(data);
    } else if (backendRes.status === 401) {
      const errJson = await backendRes.json().catch(() => null);
      return res.status(401).json(errJson || { error: 'Unauthorized session.' });
    }
  } catch {
    // If FastAPI is temporarily unreachable, fallback to verified local ledger
  }

  // 2. Fallback to local verified session
  const authenticatedSid = getAuthenticatedSession(req);
  if (!authenticatedSid) {
    if (clientSid || clientToken) {
      return res.status(401).json({
        error: 'Unauthorized: Invalid or forged session authentication credentials.',
        detail: 'Unauthorized: Invalid or forged session authentication credentials.',
      });
    }
    return res.json([]);
  }

  const userScans = scanHistory.filter((r) => r.session_id === authenticatedSid);
  res.json(userScans.slice(0, 30));
});

// Single scan retrieval with session-ownership isolation
app.get('/api/scan/:scan_id', rateLimit(60), async (req, res) => {
  const scanId = req.params.scan_id;
  let clientSid = ((req.headers['x-session-id'] as string) || (req.query.session_id as string) || '').trim();
  let clientToken = ((req.headers['x-session-token'] as string) || (req.headers['x-session-signature'] as string) || (req.query.session_token as string) || '').trim();

  const authHeader = (req.headers['authorization'] as string) || '';
  if (authHeader.startsWith('Session ')) {
    const tokenPart = authHeader.substring(8).trim();
    if (!clientToken) clientToken = tokenPart;
    if (!clientSid && tokenPart.includes('.')) clientSid = tokenPart.split('.')[0];
  }

  if (clientSid && !clientToken) {
    return res.status(401).json({
      error: 'Unauthorized: Client-supplied X-Session-ID cannot be used without a valid X-Session-Token.',
      detail: 'Unauthorized: Client-supplied X-Session-ID cannot be used without a valid X-Session-Token.',
    });
  }

  const authenticatedSid = getAuthenticatedSession(req);

  // Check local in-memory scan ledger first
  const localScan = scanHistory.find((r) => r.scan_id === scanId);
  if (localScan) {
    if (localScan.session_id) {
      if (!authenticatedSid) {
        return res.status(401).json({
          error: 'Unauthorized: Valid session authentication required to access this scan report.',
          detail: 'Unauthorized: Valid session authentication required to access this scan report.',
        });
      }
      if (authenticatedSid !== localScan.session_id) {
        return res.status(403).json({
          error: "Forbidden: You do not have permission to access another session's scan report.",
          detail: "Forbidden: You do not have permission to access another session's scan report.",
        });
      }
    }
    return res.json(localScan);
  }

  // Proxy to FastAPI backend if not in local ledger
  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/scan/${scanId}`, {
      headers: getInternalHeaders(req, {
        'Accept': 'application/json',
      }),
      signal: AbortSignal.timeout(10000),
    });
    const data = await backendRes.json().catch(() => null);
    return res.status(backendRes.status).json(data);
  } catch (err: any) {
    return res.status(404).json({ error: 'Scan report not found' });
  }
});

// CHAT ENDPOINT — Proxied securely to FastAPI with internal auth, session tracking & streaming support
app.post(['/api/chat', '/api/chat/stream'], rateLimit(40), async (req, res) => {
  const body = req.body || {};
  if (typeof body.message !== 'string' || !body.message.trim()) {
    return res.status(400).json({ detail: 'Message cannot be empty.' });
  }

  const isStream = Boolean(body.stream || req.path.endsWith('/stream'));
  const sessionId = getSessionIdFromReq(req);

  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/chat`, {
      method: 'POST',
      headers: getInternalHeaders(req, {
        'Content-Type': 'application/json',
        'Accept': isStream ? 'text/event-stream, application/json' : 'application/json',
        ...(sessionId ? { 'X-Session-ID': sessionId } : {}),
      }),
      body: JSON.stringify({
        message: body.message,
        history: Array.isArray(body.history) ? body.history : [],
        context: body.context ?? null,
        stream: isStream,
      }),
      signal: AbortSignal.timeout(70000),
    });

    const contentType = backendRes.headers.get('content-type') || 'application/json';
    res.status(backendRes.status);
    res.setHeader('Content-Type', contentType);

    if (contentType.includes('text/event-stream') && backendRes.body) {
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      if (typeof (res as any).flushHeaders === 'function') {
        (res as any).flushHeaders();
      }
      const reader = backendRes.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      return res.end();
    }

    const responseBody = await backendRes.text();
    return res.send(responseBody);
  } catch (err: any) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    console.error('VibeSec FastAPI chat proxy failed:', timedOut ? 'timeout' : (err?.code || err?.name || 'network error'));
    return res.status(timedOut ? 504 : 503).json({
      detail: timedOut
        ? 'The AI request exceeded the Express proxy timeout.'
        : `VibeSec FastAPI is unavailable at ${FASTAPI_URL}. Ensure the backend is running.`,
    });
  }
});

// REMEDIATION: Propose Patch proxy to FastAPI with internal auth
app.post('/api/remediate/propose-patch', rateLimit(30), async (req, res) => {
  const sessionId = getSessionIdFromReq(req);
  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/remediate/propose-patch`, {
      method: 'POST',
      headers: getInternalHeaders(req, {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(sessionId ? { 'X-Session-ID': sessionId } : {}),
      }),
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(100000),
    });

    const responseBody = await backendRes.text();
    res.status(backendRes.status);
    res.setHeader('Content-Type', backendRes.headers.get('content-type') || 'application/json');
    return res.send(responseBody);
  } catch (err: any) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    console.error('VibeSec propose-patch proxy failed:', timedOut ? 'timeout' : (err?.code || err?.name || 'network error'));
    return res.status(timedOut ? 504 : 503).json({
      success: false,
      error: timedOut
        ? 'Patch generation timed out waiting for AI inference.'
        : `VibeSec FastAPI backend is offline at ${FASTAPI_URL}. Ensure FastAPI is operational.`,
      can_retry: true,
    });
  }
});

// REMEDIATION: Verify Patch proxy to FastAPI with internal auth
app.post('/api/remediate/verify-patch', rateLimit(30), async (req, res) => {
  const body = req.body || {};
  if (!body.user_approved) {
    return res.status(400).json({
      verification_state: 'VERIFICATION FAILED',
      verified: false,
      error: 'Explicit user approval is required before applying and verifying changes.',
      disclaimer: 'Passing static checks does not prove the code is completely secure.',
    });
  }

  const sessionId = getSessionIdFromReq(req);

  try {
    const backendRes = await fetch(`${FASTAPI_URL}/api/remediate/verify-patch`, {
      method: 'POST',
      headers: getInternalHeaders(req, {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(sessionId ? { 'X-Session-ID': sessionId } : {}),
      }),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });

    const responseBody = await backendRes.text();
    res.status(backendRes.status);
    res.setHeader('Content-Type', backendRes.headers.get('content-type') || 'application/json');
    return res.send(responseBody);
  } catch (err: any) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    console.error('VibeSec verify-patch proxy failed:', timedOut ? 'timeout' : (err?.code || err?.name || 'network error'));
    return res.status(timedOut ? 504 : 503).json({
      verification_state: 'VERIFICATION FAILED',
      verified: false,
      error: timedOut
        ? 'Deterministic verification timed out.'
        : `VibeSec FastAPI backend is offline at ${FASTAPI_URL}.`,
      disclaimer: 'Passing static checks does not prove the code is completely secure.',
    });
  }
});

// 7. PROJECT ZIP GENERATOR (Download complete React/Vite/FastAPI project bundle)
app.get('/api/download-project-zip', async (req, res) => {
  try {
    const zip = new JSZip();

    const rootDir = __dirname;
    const EXCLUDED_DIRS = new Set([
      'node_modules', '.git', 'dist', '.venv', 'venv', '__pycache__',
      '.next', '.semgrep-env', 'brain', '.vscode', '.idea'
    ]);
    const EXCLUDED_EXTENSIONS = new Set(['.pyc', '.pyo', '.token', '.tmp']);
    const EXCLUDED_FILES = new Set(['.env', '.proxy_token']);

    function addDirToZip(dirPath: string, zipFolder: JSZip) {
      if (!fs.existsSync(dirPath)) return;
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (EXCLUDED_DIRS.has(entry.name) || EXCLUDED_FILES.has(entry.name)) continue;
        const fullPath = path.join(dirPath, entry.name);
        if (entry.isDirectory()) {
          addDirToZip(fullPath, zipFolder.folder(entry.name)!);
        } else {
          const ext = path.extname(entry.name).toLowerCase();
          if (EXCLUDED_EXTENSIONS.has(ext)) continue;
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > 15 * 1024 * 1024) continue; // Skip large binaries
            const fileData = fs.readFileSync(fullPath);
            zipFolder.file(entry.name, fileData);
          } catch {
            // Ignore unreadable or locked file
          }
        }
      }
    }

    addDirToZip(rootDir, zip);

    // Also include a comprehensive README for Kartikey's NIELIT Major Project
    zip.file('README.md', `# VibeSec — AI-Powered Security Scanner for AI-Generated Code
NIELIT Gorakhpur Major Project
Author: Kartikey Vishwakarma

## Overview
VibeSec is an enterprise-grade cybersecurity scanning engine tailored for detecting vulnerabilities introduced by LLMs and AI code assistants.

### Core Architecture
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons, Recharts
- **API Gateway**: Express, TypeScript, Server-Sent Events, Rate Limiting
- **Authoritative Scanner Engine**: FastAPI, Python 3.11, AST Analysis, Semgrep Engine
- **AI Model**: Ollama (qwen2.5-coder:7b) via Authenticated Local Proxy & Cloudflare Tunnel

## Running Backend (FastAPI)
\`\`\`bash
cd vibesec/backend
python -m venv .venv
.\\.venv\\Scripts\\activate  # on Windows (or source .venv/bin/activate on Linux/Mac)
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
\`\`\`

## Running Frontend & Gateway (React + Vite + Express)
\`\`\`bash
npm install
npm run dev
\`\`\`
Visit http://localhost:3000
`);

    const zipContent = await zip.generateAsync({ type: 'nodebuffer' });
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="vibesec-nielit-project.zip"');
    res.send(zipContent);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to generate project archive', detail: err?.message });
  }
});

// Mount Vite or static build
async function setupServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`VibeSec Server operational on http://0.0.0.0:${PORT}`);
  });
  // Prevent socket/connection timeouts during slow 100MB uploads (Render allows up to 100 minutes)
  server.requestTimeout = 10 * 60 * 1000; // 10 minutes
  server.headersTimeout = 65 * 1000;
  server.keepAliveTimeout = 60 * 1000;
  server.timeout = 10 * 60 * 1000;
}

setupServer();
