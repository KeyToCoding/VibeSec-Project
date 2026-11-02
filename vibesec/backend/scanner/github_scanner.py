"""
VibeSec GitHub Public Repository Scanner
Uses GitHub REST API to traverse repository file trees, strictly skips vendor directories,
identifies committed sensitive files (.env, credentials), downloads source files,
and performs static + AI security audits.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import re
import time
import httpx
import logging
from typing import Dict, Any, List
from .code_scanner import scan_code, compute_severity_counts
from .file_scanner import SUPPORTED_EXTENSIONS, should_skip_path
from .url_scanner import check_secrets_in_text

logger = logging.getLogger("vibesec.github_scanner")


def parse_github_url(repo_url: str):
    """Extract owner and repo name from GitHub URL."""
    repo_url = repo_url.strip().rstrip("/")
    pattern = r"github\.com[/:]([\w\-\.]+)/([\w\-\.]+)"
    match = re.search(pattern, repo_url)
    if not match:
        raise ValueError("Invalid GitHub URL. Must be in format https://github.com/owner/repo")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


async def scan_github(repo_url: str, max_files: int = 15) -> Dict[str, Any]:
    """
    Perform security audit on a public GitHub repository.
    Fetches git tree via GitHub API and audits up to max_files source files.
    """
    start_time = time.time()
    owner, repo = parse_github_url(repo_url)

    files_scanned: List[str] = []
    files_skipped: List[str] = []
    all_vulnerabilities: List[Dict[str, Any]] = []
    all_hallucinations: List[Dict[str, Any]] = []

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VibeSec-GitHub-Auditor/1.0"
    }

    async with httpx.AsyncClient(headers=headers, timeout=20.0) as client:
        # 1. Fetch repo metadata to determine default branch
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo}"
        repo_resp = await client.get(repo_info_url)
        if repo_resp.status_code != 200:
            raise ValueError(f"GitHub repository '{owner}/{repo}' could not be accessed. (Status: {repo_resp.status_code})")

        repo_data = repo_resp.json()
        default_branch = repo_data.get("default_branch", "main")

        # 2. Fetch git tree recursively
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
        tree_resp = await client.get(tree_url)
        if tree_resp.status_code != 200:
            # Fallback to HEAD if branch failed
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
            tree_resp = await client.get(tree_url)

        if tree_resp.status_code != 200:
            raise ValueError(f"Failed to fetch repository tree: HTTP {tree_resp.status_code}")

        tree_items = tree_resp.json().get("tree", [])

        # Filter candidates
        candidates = []
        for item in tree_items:
            path = item.get("path", "")
            item_type = item.get("type", "")

            if item_type != "blob":
                continue

            # Strict skip filter
            if should_skip_path(path):
                files_skipped.append(path)
                continue

            # Check committed .env files
            filename_only = path.split("/")[-1].lower()
            if filename_only.startswith(".env") or filename_only == ".env":
                all_vulnerabilities.append({
                    "title": "Committed Sensitive Environment File (.env)",
                    "severity": "critical",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "description": f"Environment file '{path}' is committed directly to public source control.",
                    "attack_scenario": "Attackers can read private secrets, database connection strings, and production keys.",
                    "file": path,
                    "line_hint": 1,
                    "confidence": "high",
                    "fix": "Remove .env from Git history using git-filter-repo and add .env to .gitignore."
                })
                files_scanned.append(path)
                continue

            # Check supported extensions
            dot_idx = path.rfind(".")
            ext = path[dot_idx:].lower() if dot_idx != -1 else ""
            if ext in SUPPORTED_EXTENSIONS or filename_only == "package.json":
                candidates.append((path, ext))
            else:
                files_skipped.append(path)

        # 3. Download and scan candidates up to max_files
        for path, ext in candidates[:max_files]:
            files_scanned.append(path)
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{path}"
            try:
                raw_resp = await client.get(raw_url)
                if raw_resp.status_code == 200:
                    code_text = raw_resp.text

                    # Check secrets
                    secrets = check_secrets_in_text(code_text, path)
                    all_vulnerabilities.extend(secrets)

                    # Scan code
                    lang = SUPPORTED_EXTENSIONS.get(ext, "javascript")
                    scan_rep = await scan_code(code_text[:50000], language=lang, filename=path)
                    all_vulnerabilities.extend(scan_rep.get("vulnerabilities", []))
                    all_hallucinations.extend(scan_rep.get("hallucinated_packages", []))
            except Exception as e_file:
                logger.warning(f"Error fetching raw file {path}: {e_file}")

    scan_time = round(time.time() - start_time, 2)
    severity_counts = compute_severity_counts(all_vulnerabilities)

    return {
        "repo_url": repo_url,
        "owner": owner,
        "repo": repo,
        "branch": default_branch,
        "input_type": "github",
        "language": "multi-language",
        "vulnerabilities": all_vulnerabilities,
        "hallucinated_packages": all_hallucinations,
        "severity_counts": severity_counts,
        "files_scanned": len(files_scanned),
        "files_scanned_list": files_scanned,
        "files_skipped": files_skipped[:50],
        "summary": f"Scanned repo '{owner}/{repo}' ({default_branch}). Audited {len(files_scanned)} files. Found {len(all_vulnerabilities)} vulnerabilities in {scan_time}s.",
        "scan_time_seconds": scan_time
    }
