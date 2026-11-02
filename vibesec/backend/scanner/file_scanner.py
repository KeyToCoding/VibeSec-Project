"""
VibeSec File and ZIP Upload Scanner
Extracts archives and recursively scans source files.
Strictly ignores vendor folders (node_modules, .git, venv) to maximize performance.
Inspects package.json dependencies against npm registry for hallucinations.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import os
import uuid
import json
import shutil
import zipfile
import time
import httpx
import logging
from typing import Dict, Any, List, Set, Optional
from .code_scanner import scan_code, compute_severity_counts
from .hallucination import check_npm_package
try:
    from models.llm_chain import call_llm
    from models.prompts import HALLUCINATION_PROMPT
except ImportError:
    from ..models.llm_chain import call_llm
    from ..models.prompts import HALLUCINATION_PROMPT

logger = logging.getLogger("vibesec.file_scanner")

SKIPPED_DIR_PARTS = [
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "coverage", ".idea", ".vscode"
]

SKIPPED_FILE_SUFFIXES = [
    ".min.js", ".bundle.js", ".min.css", ".map", ".lock", "package-lock.json", "yarn.lock"
]

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".env": "dotenv",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json"
}


def should_skip_path(path: str) -> bool:
    """Determine whether path falls into vendor / minified / build directories."""
    normalized = path.replace("\\", "/").lower()
    for part in SKIPPED_DIR_PARTS:
        if f"/{part}/" in f"/{normalized}/" or normalized.startswith(f"{part}/"):
            return True
    for suffix in SKIPPED_FILE_SUFFIXES:
        if normalized.endswith(suffix):
            return True
    return False


async def check_package_json(content: str, rel_path: str) -> List[Dict[str, Any]]:
    """Scan package.json dependencies for hallucinated npm packages."""
    hallucinations = []
    try:
        data = json.loads(content)
        deps = list(data.get("dependencies", {}).keys()) + list(data.get("devDependencies", {}).keys())
        async with httpx.AsyncClient(timeout=5.0) as client:
            for pkg in deps:
                if pkg.startswith("@types/"):
                    continue
                exists = await check_npm_package(client, pkg)
                if not exists:
                    prompt = HALLUCINATION_PROMPT.format(package_name=pkg)
                    try:
                        explanation, _ = await call_llm(prompt, task="package_json_check")
                    except Exception:
                        explanation = f"Package '{pkg}' is missing from the npm registry. Potential supply chain squatting vector."

                    hallucinations.append({
                        "package": pkg,
                        "ecosystem": "npm",
                        "status": "hallucinated",
                        "severity": "critical",
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "title": f"Hallucinated Dependency in package.json: {pkg}",
                        "description": f"The dependency '{pkg}' specified in {rel_path} was not found on registry.npmjs.org.",
                        "attack_scenario": "Threat actors can publish this unpublished package name and execute rogue postinstall lifecycle hooks.",
                        "risk_analysis": explanation.strip().replace('"', ''),
                        "file": rel_path,
                        "line_hint": 1,
                        "confidence": "high",
                        "fix": f"Remove '{pkg}' from package.json or correct the package name."
                    })
    except Exception as e:
        logger.warning(f"Error parsing package.json {rel_path}: {e}")
    return hallucinations


import tempfile

async def scan_upload(
    file_bytes: Optional[bytes] = None,
    filename: str = "upload.zip",
    file_path: Optional[str] = None
) -> Dict[str, Any]:
    """Process an uploaded single file or ZIP bundle with Zip-Slip, Zip-Bomb, and bounded-memory disk-spooled streaming."""
    start_time = time.time()
    scan_id = str(uuid.uuid4())
    temp_dir = tempfile.mkdtemp(prefix=f"vibesec_scan_{scan_id}_")

    files_scanned: List[str] = []
    files_skipped: List[str] = []
    all_vulnerabilities: List[Dict[str, Any]] = []
    all_hallucinations: List[Dict[str, Any]] = []

    try:
        if filename.lower().endswith(".zip"):
            if file_path and os.path.exists(file_path):
                zip_path = file_path
                created_temp_zip = False
            elif file_bytes is not None:
                zip_path = os.path.join(temp_dir, "archive.zip")
                with open(zip_path, "wb") as f:
                    f.write(file_bytes)
                created_temp_zip = True
            else:
                raise ValueError("No file content provided for upload scan.")

            total_uncompressed = 0
            MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024  # 250 MB
            MAX_ARCHIVE_FILES = 500  # Up to 500 files
            extracted_count = 0

            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    if member.is_dir():
                        continue

                    # Zip-Slip Protection: verify resolved target path is strictly inside temp_dir
                    target_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                    if not target_path.startswith(os.path.abspath(temp_dir) + os.sep):
                        files_skipped.append(f"{member.filename} (skipped: illegal path traversal)")
                        continue

                    total_uncompressed += member.file_size
                    extracted_count += 1
                    if total_uncompressed > MAX_UNCOMPRESSED_BYTES or extracted_count > MAX_ARCHIVE_FILES:
                        reason = (
                            f"exceeds {MAX_UNCOMPRESSED_BYTES // (1024*1024)}MB uncompressed safety ceiling"
                            if total_uncompressed > MAX_UNCOMPRESSED_BYTES
                            else f"exceeds safety ceiling of {MAX_ARCHIVE_FILES} extracted files"
                        )
                        all_vulnerabilities.append({
                            "title": "Decompression Resource Limit Reached (Zip Bomb Protection)",
                            "severity": "high",
                            "owasp": "A05:2021-Security Misconfiguration",
                            "description": f"Uploaded archive {reason}. Scanning halted on remainder.",
                            "attack_scenario": "Exhausting host disk or RAM via nested or oversized compressed payloads.",
                            "file": filename,
                            "line_hint": 1,
                            "confidence": "high",
                            "fix": f"Keep archives under {MAX_UNCOMPRESSED_BYTES // (1024*1024)}MB total uncompressed source code and under {MAX_ARCHIVE_FILES} files."
                        })
                        break

                    zip_ref.extract(member, temp_dir)

            if created_temp_zip:
                try:
                    os.remove(zip_path)
                except OSError:
                    pass

            # Walk extracted files
            for root, dirs, files in os.walk(temp_dir):
                # Prune skipped directories in-place
                dirs[:] = [d for d in dirs if not should_skip_path(d)]

                for f in files:
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, temp_dir)

                    if should_skip_path(rel_p):
                        files_skipped.append(rel_p)
                        continue

                    _, ext = os.path.splitext(f.lower())
                    if f.lower() == "package.json":
                        files_scanned.append(rel_p)
                        with open(full_p, "r", encoding="utf-8", errors="ignore") as pf:
                            pj_text = pf.read(200000)
                        pj_findings = await check_package_json(pj_text, rel_p)
                        all_hallucinations.extend(pj_findings)
                        all_vulnerabilities.extend(pj_findings)
                        continue

                    if ext not in SUPPORTED_EXTENSIONS and not f.startswith(".env"):
                        files_skipped.append(rel_p)
                        continue

                    if len(files_scanned) >= MAX_ARCHIVE_FILES:
                        files_skipped.append(f"{rel_p} (skipped: archive file scan ceiling of {MAX_ARCHIVE_FILES} reached)")
                        break

                    files_scanned.append(rel_p)
                    lang = SUPPORTED_EXTENSIONS.get(ext, "python" if ext == ".py" else "javascript")
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as src_f:
                        code_content = src_f.read(60000)

                    # Scan code chunk
                    file_res = await scan_code(code_content, language=lang, filename=rel_p)
                    all_vulnerabilities.extend(file_res.get("vulnerabilities", []))
                    all_hallucinations.extend(file_res.get("hallucinated_packages", []))

        else:
            # Single file upload
            files_scanned.append(filename)
            _, ext = os.path.splitext(filename.lower())
            lang = SUPPORTED_EXTENSIONS.get(ext, "python" if ext == ".py" else "javascript")
            if file_path and os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as sf:
                    code_text = sf.read(100000)
            elif file_bytes is not None:
                code_text = file_bytes.decode("utf-8", errors="ignore")
            else:
                code_text = ""

            if filename.lower() == "package.json":
                pj_findings = await check_package_json(code_text, filename)
                all_hallucinations.extend(pj_findings)
                all_vulnerabilities.extend(pj_findings)
            else:
                file_res = await scan_code(code_text, language=lang, filename=filename)
                all_vulnerabilities.extend(file_res.get("vulnerabilities", []))
                all_hallucinations.extend(file_res.get("hallucinated_packages", []))

    finally:
        # Cleanup temp directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    scan_time = round(time.time() - start_time, 2)
    severity_counts = compute_severity_counts(all_vulnerabilities)

    return {
        "scan_id": scan_id,
        "input_type": "upload",
        "filename": filename,
        "language": "multi-file",
        "vulnerabilities": all_vulnerabilities,
        "hallucinated_packages": all_hallucinations,
        "severity_counts": severity_counts,
        "files_scanned": len(files_scanned),
        "files_scanned_list": files_scanned[:50],
        "files_skipped": files_skipped[:50],
        "summary": f"Uploaded bundle '{filename}' scanned: {len(files_scanned)} files audited, {len(files_skipped)} vendor files skipped, {len(all_vulnerabilities)} vulnerabilities identified.",
        "scan_time_seconds": scan_time
    }
