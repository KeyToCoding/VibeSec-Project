"""VibeSec Environment File & Secret Detector
Accurately distinguishes safe template files (.env.example, .env.sample, .env.template)
from committed runtime environment files (.env, .env.local, .env.production).
Inspects file content for real credentials, API keys, passwords, and private tokens
while filtering out placeholders (YOUR_API_KEY, CHANGE_ME, your-random-*, etc.).

Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import re
from typing import Dict, Any, List, Tuple, Optional

# High-confidence secret patterns
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"(sk-[a-zA-Z0-9]{20,})", "OpenAI / Stripe Secret Key"),
    (r"(AIza[0-9A-Za-z-_]{35})", "Google Cloud API Key"),
    (r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})", "GitHub Personal Access Token"),
    (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID"),
    (r"(sq0atp-[0-9A-Za-z\-_]{22})", "Square Access Token"),
    (r"(eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]+)", "Exposed JWT Token"),
    (r"(xox[baprs]-[0-9a-zA-Z]{10,48})", "Slack Token"),
    (r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----", "Private Cryptographic Key"),
]

# Sensitive environment variable keys
SENSITIVE_KEY_PATTERNS = [
    r"SECRET", r"PASSWORD", r"PASSWD", r"TOKEN", r"PRIVATE_KEY", r"AUTH",
    r"CREDENTIAL", r"API_KEY", r"ACCESS_KEY", r"DATABASE_URL", r"MONGODB_URI",
    r"REDIS_URL", r"DB_PASS", r"MASTER_KEY", r"ENCRYPTION_KEY", r"PROXY_TOKEN"
]
SENSITIVE_KEY_RE = re.compile("|".join(SENSITIVE_KEY_PATTERNS), re.IGNORECASE)

# Placeholder keywords and patterns
PLACEHOLDER_SUBSTRINGS = [
    "your-", "your_", "your ", "<your",
    "change_me", "changeme", "change-me", "change_this",
    "replace_me", "replaceme", "replace-me", "replace_this",
    "insert_here", "insert_", "insert-", "enter-your", "enter_your",
    "placeholder", "example", "sample", "dummy", "fake", "todo", "tbd",
    "xxx", "xxxx", "secret_here", "key_here", "token_here", "password_here",
    "your-random-", "your-strong-", "your-secret-", "your_secret_",
    "my-secret", "my_secret", "some-secret", "some_secret",
    "postgres://user:password@", "mongodb://localhost", "localhost", "127.0.0.1",
    "http://", "https://", "not-a-real", "test-token"
]


def is_env_template_filename(path: str) -> bool:
    """Check if the filename indicates an example or template."""
    if not path:
        return False
    normalized = path.replace("\\", "/").lower()
    filename = normalized.split("/")[-1]

    # Exact or suffix matches
    if filename in (
        ".env.example", ".env.sample", ".env.template", ".env.dist",
        ".env.defaults", ".env.sample.local", ".env.test"
    ):
        return True
    if re.search(r"\.env\.(example|sample|template|dist|defaults)$", filename):
        return True
    if re.search(r"^(example|sample|template)\.env$", filename):
        return True
    if filename.endswith(".example") or filename.endswith(".sample") or filename.endswith(".template"):
        return True
    return False


def is_committed_env_filename(path: str) -> bool:
    """Check if the filename indicates an actual runtime .env file (not a template)."""
    if not path:
        return False
    normalized = path.replace("\\", "/").lower()
    filename = normalized.split("/")[-1]
    if is_env_template_filename(filename):
        return False
    if filename == ".env":
        return True
    if filename.startswith(".env."):
        # e.g., .env.local, .env.production, .env.development, .env.staging, .env.prod, .env.dev
        return True
    return False


COMMON_SOURCE_CODE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".cc", ".cxx",
    ".h", ".hpp", ".rs", ".swift", ".kt", ".kts", ".html", ".htm",
    ".css", ".scss", ".sass", ".less", ".vue", ".svelte", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".sql", ".r", ".dart",
    ".lua", ".pl", ".pm", ".ex", ".exs", ".erl", ".hrl", ".clj",
    ".cljs", ".elm", ".fs", ".hs", ".asm", ".sol"
}


def is_source_code_file(path: str) -> bool:
    """Determine if a file is an application source-code file.

    Application source files (e.g. app.py, index.js, server.ts, main.go)
    must NEVER be removed from Git tracking or added to .gitignore merely
    because they contain a hardcoded credential.
    """
    if not path:
        return False
    normalized = path.replace("\\", "/").lower()
    filename = normalized.split("/")[-1]

    if filename in ("dockerfile", "makefile", "gemfile", "rakefile", "cmakelists.txt"):
        return True

    dot_idx = filename.rfind(".")
    if dot_idx != -1:
        ext = filename[dot_idx:]
        if ext in COMMON_SOURCE_CODE_EXTENSIONS:
            return True

    return False


def is_sensitive_config_file(path: str) -> bool:
    """Determine if a file is a sensitive credential/secret configuration file.

    Only genuine secret files (.env, private keys, service account JSON)
    should ever be untracked (git rm --cached) and added to .gitignore.
    Application source files (app.py) and documentation templates (.env.example)
    are strictly excluded.
    """
    if not path:
        return False
    normalized = path.replace("\\", "/").lower()
    filename = normalized.split("/")[-1]

    # Explicitly exclude templates
    if is_env_template_filename(filename):
        return False

    # Explicitly exclude application source code files (e.g., app.py, config.py)
    if is_source_code_file(filename):
        return False

    # Runtime environment files (.env, .env.local, .env.production, etc.)
    if is_committed_env_filename(filename):
        return True

    # Cryptographic private keys
    if filename in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
        return True
    if any(filename.endswith(ext) for ext in (".pem", ".key", ".pkcs12", ".pfx", ".p12")):
        return True

    # Dedicated credentials, tokens, service accounts
    if filename in (
        "credentials.json", "service-account.json", "service_account.json",
        "secrets.json", "token.json", "client_secret.json", "client_secrets.json",
        ".htpasswd", "htpasswd", "shadow", "master.key"
    ):
        return True
    if re.search(r"(service[-_]account|client[-_]secret|google[-_]credentials|firebase[-_]adminsdk).*\.json$", filename):
        return True

    # Package registry / tool secrets
    if filename in (".npmrc", ".pypirc", ".dockercfg"):
        return True

    return False


def classify_file_for_remediation(path: str, title: str = "") -> str:
    """Classify a finding target for safe remediation guidance.

    Returns:
        'source_code'      -> Application source files (e.g. app.py, server.ts).
                              Keep in Git; extract secret to environment variable.
        'sensitive_config' -> Pure credentials file (e.g. .env, id_rsa).
                              Untrack with git rm --cached and add to .gitignore.
        'env_template'     -> Documentation template (e.g. .env.example).
                              Keep in Git; sanitize real secret to placeholder.
        'generic'          -> Other files.
    """
    if not path:
        return "generic"
    if is_env_template_filename(path):
        return "env_template"
    if is_source_code_file(path):
        return "source_code"
    if is_sensitive_config_file(path):
        return "sensitive_config"
    return "generic"



def is_placeholder_value(val: str) -> bool:
    """Determine if an environment variable value is a dummy/template placeholder."""
    cleaned = val.strip().strip("'\"").strip()
    if not cleaned:
        return True

    # Check for angle brackets, braces, parentheses placeholders: <your_key>, [key], {key}, *(...)*
    if (
        re.match(r"^<.*>$", cleaned)
        or re.match(r"^\[.*\]$", cleaned)
        or re.match(r"^\{.*\}$", cleaned)
        or re.match(r"^\*.*\*$", cleaned)
    ):
        return True
    if cleaned.startswith("(") and cleaned.endswith(")"):
        return True

    lower = cleaned.lower()
    for sub in PLACEHOLDER_SUBSTRINGS:
        if sub in lower:
            return True

    # Common non-secret configuration values
    if lower in (
        "true", "false", "null", "none", "undefined",
        "dev", "prod", "test", "local", "development", "production", "default",
        "development_mode", "production_mode"
    ):
        return True
    if lower.isdigit():
        return True

    return False


def inspect_env_file_content(content: str, path: str) -> List[Dict[str, Any]]:
    """
    Inspect the content of an environment or template file.
    Returns findings if real credentials or private keys are discovered.
    Safe templates with placeholders produce NO findings.
    """
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()
    is_template = is_env_template_filename(path)
    is_runtime_env = is_committed_env_filename(path)

    real_secrets_found: List[Tuple[int, str, str, str]] = []  # (line_num, line_str, key_name, secret_type)

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # 1. High-confidence regex match
        matched_token = False
        for pattern_str, secret_desc in SECRET_PATTERNS:
            match = re.search(pattern_str, stripped)
            if match:
                token_val = match.group(0)
                if not is_placeholder_value(token_val):
                    real_secrets_found.append((idx, stripped, "TOKEN", secret_desc))
                    matched_token = True
                    break
        if matched_token:
            continue

        # 2. Key-Value assignment check: KEY=VALUE
        if "=" in stripped:
            parts = stripped.split("=", 1)
            key = parts[0].strip()
            val = parts[1].strip()

            if SENSITIVE_KEY_RE.search(key):
                if not is_placeholder_value(val):
                    # Actual secret assigned!
                    real_secrets_found.append((idx, stripped, key, "Sensitive Credential"))

    # Case A: Template file (.env.example, .env.sample, etc.)
    if is_template:
        for line_num, line_str, key_name, secret_type in real_secrets_found:
            findings.append({
                "title": f"Exposed Credential in Environment Template: {key_name}",
                "severity": "critical",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "description": f"Real credential or private key was found committed in environment template '{path}' (line {line_num}).",
                "attack_scenario": "Developers inadvertently committed genuine API tokens or passwords into documentation templates.",
                "file": path,
                "line_hint": line_num,
                "code_snippet": line_str,
                "confidence": "high",
                "fix": f"Replace the real value of {key_name} with a safe placeholder (e.g. YOUR_{key_name}) and revoke the exposed credential."
            })
        return findings

    # Case B: Committed runtime .env file (.env, .env.local, .env.production, etc.)
    if is_runtime_env or path.lower().endswith(".env"):
        if real_secrets_found:
            first_line_num, first_line_str, first_key, _ = real_secrets_found[0]
            evidence_snippet = "\n".join([f"Line {ln}: {ls}" for ln, ls, _, _ in real_secrets_found[:5]])
            findings.append({
                "title": "Committed Sensitive Environment File (.env)",
                "severity": "critical",
                "owasp": "A05:2021-Security Misconfiguration",
                "description": f"Active environment credentials file '{path}' containing live credentials was committed to source control.",
                "attack_scenario": "Attackers scraping repository history can extract database credentials, production API tokens, and secret keys.",
                "file": path,
                "line_hint": first_line_num,
                "code_snippet": evidence_snippet,
                "confidence": "high",
                "fix": "Remove the environment file from Git history using git-filter-repo, add .env to .gitignore, and revoke exposed secrets immediately."
            })

    return findings
