"""
VibeSec Package Hallucination & Supply Chain Attack Checker
Extracts imported packages from AI-generated code and verifies existence
against public package registries (npm registry & PyPI).
Detects 'slopsquatting' and package hallucinations that attackers exploit to inject malware.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import re
import asyncio
import httpx
import logging
from typing import List, Dict, Any, Set
try:
    from models.llm_chain import call_llm
    from models.prompts import HALLUCINATION_PROMPT, PYPI_HALLUCINATION_PROMPT
except ImportError:
    from ..models.llm_chain import call_llm
    from ..models.prompts import HALLUCINATION_PROMPT, PYPI_HALLUCINATION_PROMPT

logger = logging.getLogger("vibesec.hallucination")

NODE_BUILTINS: Set[str] = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "path/posix", "path/win32", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "stream/promises", "string_decoder", "timers", "timers/promises", "tls",
    "trace_events", "tty", "url", "util", "util/types", "v8", "vm", "wasi",
    "worker_threads", "zlib"
}

PYTHON_STDLIB: Set[str] = {
    "abc", "argparse", "array", "ast", "asyncio", "base64", "collections",
    "concurrent", "contextlib", "copy", "csv", "datetime", "decimal", "enum",
    "functools", "glob", "hashlib", "heapq", "hmac", "html", "http", "io",
    "itertools", "json", "logging", "math", "multiprocessing", "os", "pathlib",
    "pickle", "platform", "queue", "random", "re", "shutil", "signal", "socket",
    "sqlite3", "ssl", "string", "subprocess", "sys", "tempfile", "threading",
    "time", "traceback", "typing", "unittest", "urllib", "uuid", "warnings", "zipfile"
}


def clean_package_name(pkg: str) -> str:
    """Normalize package names by stripping trailing subpaths unless scoped."""
    pkg = pkg.strip().strip("'\"`")
    if not pkg:
        return ""
    # Scoped npm package: @org/pkg
    if pkg.startswith("@"):
        parts = pkg.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return pkg
    # Regular package: lodash/fp -> lodash
    return pkg.split("/")[0]


def extract_imports(code: str, language: str) -> List[str]:
    """Extract all third-party package names from source code."""
    packages: Set[str] = set()
    lang_lower = language.lower()

    if lang_lower in ("javascript", "typescript", "js", "ts", "jsx", "tsx"):
        # Match ES6 imports: import x from 'pkg', import { a } from "pkg", import "pkg"
        es_imports = re.findall(r'''(?:import\s+(?:[\w\s{},*]+from\s+)?|import\s*\(\s*)['"]([^'"\n]+)['"]''', code)
        # Match CommonJS require: require('pkg')
        cjs_imports = re.findall(r'''require\s*\(\s*['"]([^'"\n]+)['"]\s*\)''', code)

        for imp in es_imports + cjs_imports:
            imp = imp.strip()
            # Skip relative imports
            if imp.startswith(".") or imp.startswith("/"):
                continue
            # Skip node built-ins (including node: prefix)
            normalized = imp.replace("node:", "")
            if normalized in NODE_BUILTINS or normalized.split("/")[0] in NODE_BUILTINS:
                continue
            # Skip @types/ definitions
            if normalized.startswith("@types/"):
                continue
            cleaned = clean_package_name(normalized)
            if cleaned:
                packages.add(cleaned)

    elif lang_lower in ("python", "py"):
        # Match: import pkg, import pkg.sub, import pkg as x
        py_imports = re.findall(r'''^\s*(?:import)\s+([\w\s,]+)''', code, re.MULTILINE)
        for group in py_imports:
            for item in group.split(","):
                item = item.strip().split(" as ")[0].strip()
                root_pkg = item.split(".")[0]
                if root_pkg and root_pkg not in PYTHON_STDLIB:
                    packages.add(root_pkg)

        # Match: from pkg import ...
        py_from = re.findall(r'''^\s*from\s+([.\w]+)\s+import''', code, re.MULTILINE)
        for item in py_from:
            item = item.strip()
            if item.startswith("."):
                continue
            root_pkg = item.split(".")[0]
            if root_pkg and root_pkg not in PYTHON_STDLIB:
                packages.add(root_pkg)

    return list(packages)


async def check_npm_package(client: httpx.AsyncClient, package_name: str) -> bool:
    """Returns True if package exists on registry.npmjs.org, False if 404."""
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        res = await client.get(url, timeout=5.0)
        return res.status_code == 200
    except Exception as e:
        logger.warning(f"Error querying npm registry for {package_name}: {e}")
        # Treat network failure conservatively as existing to avoid false alarms
        return True


async def check_pypi_package(client: httpx.AsyncClient, package_name: str) -> bool:
    """Returns True if package exists on pypi.org, False if 404."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        res = await client.get(url, timeout=5.0)
        return res.status_code == 200
    except Exception as e:
        logger.warning(f"Error querying PyPI for {package_name}: {e}")
        return True


async def check_packages(code: str, language: str) -> List[Dict[str, Any]]:
    """
    Check all imported packages against upstream registries.
    Returns critical findings for any hallucinated packages with supply chain impact explanation.
    """
    packages = extract_imports(code, language)
    if not packages:
        return []

    lang_lower = language.lower()
    is_python = lang_lower in ("python", "py")
    hallucinated: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(headers={"User-Agent": "VibeSec-Scanner/1.0"}) as client:
        tasks = []
        for pkg in packages:
            if is_python:
                tasks.append((pkg, check_pypi_package(client, pkg)))
            else:
                tasks.append((pkg, check_npm_package(client, pkg)))

        results = await asyncio.gather(*(t[1] for t in tasks), return_exceptions=True)

        for (pkg, _), exists in zip(tasks, results):
            if isinstance(exists, bool) and not exists:
                # Package is hallucinated!
                logger.warning(f"DETECTED HALLUCINATED PACKAGE: {pkg}")
                prompt = (PYPI_HALLUCINATION_PROMPT if is_python else HALLUCINATION_PROMPT).format(package_name=pkg)

                try:
                    explanation, _ = await call_llm(prompt, task="hallucination_check")
                    explanation = explanation.strip().replace('"', '')
                except Exception:
                    explanation = (
                        f"The package '{pkg}' does not exist on the public registry. Attackers can register this "
                        "name ('package hallucination / slopsquatting') to execute arbitrary malicious code upon installation."
                    )

                hallucinated.append({
                    "package": pkg,
                    "ecosystem": "PyPI" if is_python else "npm",
                    "status": "hallucinated",
                    "severity": "critical",
                    "owasp": "A06:2021-Vulnerable and Outdated Components",
                    "title": f"Hallucinated Dependency: {pkg}",
                    "description": f"The package '{pkg}' was invented by AI generation and does not exist in the official {('PyPI' if is_python else 'npm')} registry.",
                    "risk_analysis": explanation,
                    "attack_scenario": f"An attacker can register '{pkg}' with malicious post-install hooks. When developers or CI/CD pipelines run install, the malicious payload compromises the server or developer workstation.",
                    "fix": f"Remove import of '{pkg}' or verify the correct library name (e.g. check standard documentation)."
                })

    return hallucinated
