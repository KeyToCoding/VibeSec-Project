"""
VibeSec GitHub Public Repository Scanner
Features:
- Primary: GitHub REST API with full User-Agent, Accept, X-GitHub-Api-Version, and optional GITHUB_TOKEN.
- Capture rate limit headers (x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset, retry-after).
- Intelligent fallback: Direct public repository archive download via codeload/archive zip.
- Zip-Slip, Zip-Bomb, file-count and archive-size protections.
- In-memory cache for recent scans (10-minute TTL).
- Clear distinction between 404 (not found), 403 (rate limited vs private), 400 (bad URL).
- Never report API errors as vulnerabilities.

Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import os
import re
import io
import time
import zipfile
import logging
from typing import Dict, Any, List, Tuple, Optional
import httpx

from .code_scanner import scan_code, compute_severity_counts
from .file_scanner import SUPPORTED_EXTENSIONS, should_skip_path
from .url_scanner import check_secrets_in_text
from .env_detector import inspect_env_file_content, is_env_template_filename, is_committed_env_filename

logger = logging.getLogger("vibesec.github_scanner")

# In-memory scan cache: (owner/repo) -> (timestamp, report_dict)
_GITHUB_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 600  # 10 minutes

# Safety ceilings for archive downloads
MAX_ARCHIVE_DOWNLOAD_BYTES = 25 * 1024 * 1024   # 25 MB max compressed
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024 # 50 MB max uncompressed
MAX_ARCHIVE_FILES = 500                          # 500 files ceiling


class GitHubScanError(Exception):
    """Base exception for GitHub scanning failures."""
    def __init__(self, message: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class GitHubRateLimitError(GitHubScanError):
    """Raised when GitHub REST API rate limit is exceeded."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=429, details=details)


class GitHubNotFoundError(GitHubScanError):
    """Raised when the specified repository does not exist."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=404, details=details)


class GitHubPermissionError(GitHubScanError):
    """Raised when the repository is private or access is forbidden."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=403, details=details)


def parse_github_url(repo_url: str) -> Tuple[str, str]:
    """Extract and validate owner and repo name from a GitHub URL."""
    if not repo_url or not isinstance(repo_url, str):
        raise GitHubScanError("Repository URL must be a non-empty string.", status_code=400)

    cleaned = repo_url.strip().rstrip("/")
    pattern = r"^(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+?)(?:\.git)?$"
    match = re.match(pattern, cleaned)
    if not match:
        raise GitHubScanError("Invalid GitHub URL. Must be in format https://github.com/owner/repo", status_code=400)

    owner, repo = match.group(1), match.group(2)
    if ".." in owner or ".." in repo:
        raise GitHubScanError("Invalid characters in GitHub owner or repository name.", status_code=400)

    return owner, repo


def get_github_headers() -> Dict[str, str]:
    """Construct standard GitHub REST API headers, attaching optional GITHUB_TOKEN."""
    headers = {
        "User-Agent": "VibeSec-GitHub-Scanner/1.0 (NIELIT Gorakhpur Major Project)",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def extract_rate_limit_headers(headers: httpx.Headers) -> Dict[str, str]:
    """Extract and format standard GitHub rate limit diagnostic headers."""
    info: Dict[str, str] = {}
    for key in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"):
        val = headers.get(key)
        if val is not None:
            info[key] = str(val)
    return info


def is_rate_limited(status_code: int, headers: httpx.Headers, body_text: str = "") -> bool:
    """Determine if a response indicates GitHub rate limiting or secondary abuse detection."""
    if status_code == 429:
        return True
    if status_code == 403:
        remaining = headers.get("x-ratelimit-remaining")
        if remaining == "0":
            return True
        lower_body = body_text.lower()
        if "rate limit" in lower_body or "secondary rate limit" in lower_body:
            return True
    return False


async def _download_and_scan_archive(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    default_branch: Optional[str] = None,
    max_files: int = 15,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], List[str]]:
    """
    Fallback: Stream public repository zip archive from codeload/archive,
    apply Zip-Slip defense and memory bounds, and audit contained source files.
    """
    archive_urls = []
    if default_branch:
        archive_urls.append(f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{default_branch}")
        archive_urls.append(f"https://github.com/{owner}/{repo}/archive/refs/heads/{default_branch}.zip")
    archive_urls.append(f"https://codeload.github.com/{owner}/{repo}/zip/HEAD")
    archive_urls.append(f"https://github.com/{owner}/{repo}/archive/HEAD.zip")

    resp: Optional[httpx.Response] = None
    last_status = 0
    headers = {"User-Agent": "VibeSec-GitHub-Scanner/1.0 (NIELIT Gorakhpur Major Project)"}

    for url in archive_urls:
        try:
            logger.info("Attempting archive download fallback: %s", url)
            r = await client.get(url, headers=headers, follow_redirects=True)
            last_status = r.status_code
            if r.status_code == 200:
                resp = r
                break
            elif r.status_code == 404:
                continue
            elif r.status_code in (401, 403):
                raise GitHubPermissionError(
                    f"Repository '{owner}/{repo}' is private or inaccessible without authentication.",
                    details={"status": r.status_code, "url": url}
                )
        except GitHubScanError:
            raise
        except Exception as exc:
            logger.warning("Archive download error for %s: %s", url, exc)

    if resp is None:
        if last_status == 404:
            raise GitHubNotFoundError(f"Repository '{owner}/{repo}' not found on GitHub.")
        raise GitHubScanError(f"Could not download repository archive for '{owner}/{repo}' (HTTP {last_status}).", status_code=502)

    content_bytes = resp.content
    if len(content_bytes) > MAX_ARCHIVE_DOWNLOAD_BYTES:
        raise GitHubScanError(
            f"Repository archive exceeds the maximum limit of {MAX_ARCHIVE_DOWNLOAD_BYTES // (1024 * 1024)}MB.",
            status_code=413
        )

    try:
        archive_zip = zipfile.ZipFile(io.BytesIO(content_bytes))
    except Exception as exc:
        raise GitHubScanError(f"Failed to unpack repository archive: {exc}", status_code=502) from exc

    namelist = archive_zip.namelist()
    if len(namelist) == 0:
        raise GitHubScanError(f"Repository '{owner}/{repo}' contains no files.", status_code=422)

    files_scanned: List[str] = []
    files_skipped: List[str] = []
    all_vulnerabilities: List[Dict[str, Any]] = []
    all_hallucinations: List[Dict[str, Any]] = []
    total_uncompressed = 0

    candidates: List[Tuple[str, str, zipfile.ZipInfo]] = []

    for info in namelist:
        if info.endswith("/"):
            continue

        # Strip repository root prefix (e.g. 'repo-HEAD/' or 'repo-main/')
        parts = info.split("/", 1)
        rel_path = parts[1] if len(parts) > 1 else parts[0]
        normalized = rel_path.replace("\\", "/")

        # Zip-Slip Defense
        if ".." in normalized or normalized.startswith("/") or normalized.startswith("../"):
            files_skipped.append(f"{rel_path} (skipped: path traversal attempt)")
            continue

        if len(files_skipped) + len(candidates) >= MAX_ARCHIVE_FILES:
            files_skipped.append(f"Remaining archive files (skipped: exceeded {MAX_ARCHIVE_FILES} files ceiling)")
            break

        # Vendor skip
        if should_skip_path(normalized):
            files_skipped.append(normalized)
            continue

        filename_only = normalized.split("/")[-1].lower()
        dot_idx = normalized.rfind(".")
        ext = normalized[dot_idx:].lower() if dot_idx != -1 else ""

        if (
            ext in SUPPORTED_EXTENSIONS
            or filename_only == "package.json"
            or filename_only.startswith(".env")
            or filename_only == ".env"
            or is_env_template_filename(normalized)
            or is_committed_env_filename(normalized)
        ):
            zip_info = archive_zip.getinfo(info)
            candidates.append((normalized, ext, zip_info))
        else:
            files_skipped.append(normalized)

    # Audit up to max_files candidate source files
    for path, ext, zip_info in candidates[:max_files]:
        if total_uncompressed + zip_info.file_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            files_skipped.append(f"{path} (skipped: archive uncompressed limit of {MAX_ARCHIVE_UNCOMPRESSED_BYTES // (1024 * 1024)}MB exceeded)")
            continue

        try:
            with archive_zip.open(zip_info) as file_entry:
                raw_bytes = file_entry.read()
                total_uncompressed += len(raw_bytes)
                code_text = raw_bytes.decode("utf-8", errors="replace")

            files_scanned.append(path)
            filename_only = path.split("/")[-1].lower()

            # Dedicated environment and template file inspection
            if (
                filename_only.startswith(".env")
                or filename_only == ".env"
                or is_env_template_filename(path)
                or is_committed_env_filename(path)
                or ext == ".env"
            ):
                env_findings = inspect_env_file_content(code_text, path)
                all_vulnerabilities.extend(env_findings)
            else:
                secrets_found = check_secrets_in_text(code_text, path)
                all_vulnerabilities.extend(secrets_found)
                lang = SUPPORTED_EXTENSIONS.get(ext, "javascript")
                scan_rep = await scan_code(code_text[:50000], language=lang, filename=path)
                all_vulnerabilities.extend(scan_rep.get("vulnerabilities", []))
                all_hallucinations.extend(scan_rep.get("hallucinated_packages", []))
        except Exception as e_file:
            logger.warning("Error scanning file '%s' from archive: %s", path, e_file)

    return all_vulnerabilities, all_hallucinations, files_scanned, files_skipped


async def scan_github(repo_url: str, max_files: int = 15) -> Dict[str, Any]:
    """
    Perform security audit on a public GitHub repository.
    1. Checks in-memory scan cache.
    2. Attempts GitHub REST API with rate-limit monitoring.
    3. Seamlessly falls back to public codeload archive download if REST API is rate-limited.
    4. Only returns a successful scan result when real repository files have been analyzed.
    """
    start_time = time.time()
    owner, repo = parse_github_url(repo_url)
    cache_key = f"{owner.lower()}/{repo.lower()}"

    # 1. Check in-memory cache
    cached = _GITHUB_CACHE.get(cache_key)
    if cached:
        cached_time, cached_report = cached
        if time.time() - cached_time < CACHE_TTL_SECONDS:
            logger.info("Serving GitHub scan result for '%s/%s' from cache", owner, repo)
            fresh_report = dict(cached_report)
            fresh_report["cached"] = True
            fresh_report["scan_time_seconds"] = 0.05
            return fresh_report

    headers = get_github_headers()
    files_scanned: List[str] = []
    files_skipped: List[str] = []
    all_vulnerabilities: List[Dict[str, Any]] = []
    all_hallucinations: List[Dict[str, Any]] = []
    default_branch = "main"
    scan_method = "rest_api"

    async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
        # Attempt REST API flow
        try:
            repo_info_url = f"https://api.github.com/repos/{owner}/{repo}"
            repo_resp = await client.get(repo_info_url, headers=headers)
            rl_headers = extract_rate_limit_headers(repo_resp.headers)

            if repo_resp.status_code == 404:
                raise GitHubNotFoundError(
                    f"GitHub repository '{owner}/{repo}' was not found. Verify the owner and repository name, and ensure the repository is public."
                )

            if is_rate_limited(repo_resp.status_code, repo_resp.headers, repo_resp.text):
                logger.warning(
                    "GitHub API rate limit reached for '%s/%s' (HTTP %d, remaining: %s). Falling back to archive download.",
                    owner, repo, repo_resp.status_code, rl_headers.get("x-ratelimit-remaining", "unknown")
                )
                scan_method = "archive_download"
                all_vulnerabilities, all_hallucinations, files_scanned, files_skipped = await _download_and_scan_archive(
                    client, owner, repo, default_branch=None, max_files=max_files
                )
            elif repo_resp.status_code in (401, 403):
                raise GitHubPermissionError(
                    f"Access to GitHub repository '{owner}/{repo}' is forbidden. Private repositories cannot be scanned without authentication.",
                    details=rl_headers
                )
            elif repo_resp.status_code != 200:
                logger.warning("GitHub API returned unexpected status %d. Falling back to archive download.", repo_resp.status_code)
                scan_method = "archive_download"
                all_vulnerabilities, all_hallucinations, files_scanned, files_skipped = await _download_and_scan_archive(
                    client, owner, repo, default_branch=None, max_files=max_files
                )
            else:
                # 200 OK: extract default branch
                repo_data = repo_resp.json()
                default_branch = repo_data.get("default_branch", "main")

                # Fetch git tree
                tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
                tree_resp = await client.get(tree_url, headers=headers)

                if is_rate_limited(tree_resp.status_code, tree_resp.headers, tree_resp.text) or tree_resp.status_code != 200:
                    logger.warning(
                        "GitHub tree API failed (status %d). Falling back to archive download.",
                        tree_resp.status_code
                    )
                    scan_method = "archive_download"
                    all_vulnerabilities, all_hallucinations, files_scanned, files_skipped = await _download_and_scan_archive(
                        client, owner, repo, default_branch=default_branch, max_files=max_files
                    )
                else:
                    tree_items = tree_resp.json().get("tree", [])
                    candidates = []
                    for item in tree_items:
                        path = item.get("path", "")
                        if item.get("type") != "blob":
                            continue

                        if should_skip_path(path):
                            files_skipped.append(path)
                            continue

                        filename_only = path.split("/")[-1].lower()
                        dot_idx = path.rfind(".")
                        ext = path[dot_idx:].lower() if dot_idx != -1 else ""
                        if (
                            ext in SUPPORTED_EXTENSIONS
                            or filename_only == "package.json"
                            or filename_only.startswith(".env")
                            or filename_only == ".env"
                            or is_env_template_filename(path)
                            or is_committed_env_filename(path)
                        ):
                            candidates.append((path, ext))
                        else:
                            files_skipped.append(path)

                    # Download candidate files
                    for path, ext in candidates[:max_files]:
                        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{path}"
                        try:
                            raw_resp = await client.get(raw_url, headers=headers)
                            if raw_resp.status_code == 200:
                                files_scanned.append(path)
                                code_text = raw_resp.text
                                filename_only = path.split("/")[-1].lower()

                                if (
                                    filename_only.startswith(".env")
                                    or filename_only == ".env"
                                    or is_env_template_filename(path)
                                    or is_committed_env_filename(path)
                                    or ext == ".env"
                                ):
                                    env_findings = inspect_env_file_content(code_text, path)
                                    all_vulnerabilities.extend(env_findings)
                                else:
                                    secrets_found = check_secrets_in_text(code_text, path)
                                    all_vulnerabilities.extend(secrets_found)
                                    lang = SUPPORTED_EXTENSIONS.get(ext, "javascript")
                                    scan_rep = await scan_code(code_text[:50000], language=lang, filename=path)
                                    all_vulnerabilities.extend(scan_rep.get("vulnerabilities", []))
                                    all_hallucinations.extend(scan_rep.get("hallucinated_packages", []))
                        except Exception as e_file:
                            logger.warning("Error fetching raw file %s: %s", path, e_file)

        except (GitHubNotFoundError, GitHubPermissionError):
            raise
        except Exception as exc:
            logger.warning("REST API traversal failed (%s). Attempting archive fallback.", exc)
            scan_method = "archive_download"
            all_vulnerabilities, all_hallucinations, files_scanned, files_skipped = await _download_and_scan_archive(
                client, owner, repo, default_branch=default_branch, max_files=max_files
            )

    # Ensure real files were analyzed
    if len(files_scanned) == 0:
        raise GitHubScanError(
            f"No scannable source code files could be downloaded from repository '{owner}/{repo}'.",
            status_code=422
        )

    scan_time = round(time.time() - start_time, 2)
    severity_counts = compute_severity_counts(all_vulnerabilities)

    result_report = {
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
        "scan_method": scan_method,
        "summary": (
            f"Audited GitHub repository '{owner}/{repo}' ({default_branch}) via {scan_method}. "
            f"Analyzed {len(files_scanned)} source files ({len(files_skipped)} vendor files skipped). "
            f"Identified {len(all_vulnerabilities)} vulnerabilities in {scan_time}s."
        ),
        "primary_model": "VibeSec GitHub Auditor",
        "scan_time_seconds": scan_time,
    }

    # Store in memory cache
    _GITHUB_CACHE[cache_key] = (time.time(), result_report)
    return result_report
