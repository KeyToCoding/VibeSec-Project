"""
VibeSec Code Scanner Orchestrator
Coordinates Semgrep static analysis, LLM vulnerability verification,
and package hallucination verification into a unified security audit report.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import time
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from .semgrep_runner import semgrep_scan
from .vuln_agent import analyze_chunk
from .hallucination import check_packages

logger = logging.getLogger("vibesec.code_scanner")


def compute_severity_counts(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate counts for critical, high, medium, low, and safe."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    if not vulnerabilities:
        counts["safe"] = 1
        return counts

    for v in vulnerabilities:
        sev = str(v.get("severity", "medium")).lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["medium"] += 1
    return counts


async def scan_code(
    code: str,
    language: str = "python",
    filename: str = "snippet",
    local_modules: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Scan a single block of code:
      1. Semgrep / Static Analysis for initial flags
      2. LLM Verification agent on each chunk (parallelized)
      3. Package hallucination check against npm/PyPI (excluding local repository modules)
    """
    start_time = time.time()
    logger.info(f"Initiating code scan for {filename} ({language}, {len(code)} bytes)")

    # Step 1: Run Semgrep outside the event loop. The CLI can take up to 30s
    # (for example while resolving remote rules); blocking here prevents unrelated
    # FastAPI requests such as /api/chat from progressing and firing their deadlines.
    semgrep_findings = await asyncio.to_thread(semgrep_scan, code, language)
    logger.info(f"Semgrep returned {len(semgrep_findings)} candidate findings")

    # Step 2: Concurrently analyze findings with VulnAgent and check hallucinated packages
    agent_tasks = [
        analyze_chunk(finding, code, language, filename)
        for finding in semgrep_findings
    ]
    hallucination_task = check_packages(code, language, local_modules=local_modules)

    # Run AI analysis and dependency check in parallel
    ai_results, hallucinated_pkgs = await asyncio.gather(
        asyncio.gather(*agent_tasks, return_exceptions=True),
        hallucination_task
    )

    verified_vulns: List[Dict[str, Any]] = []
    for item in ai_results:
        if isinstance(item, dict) and item:
            item["language"] = language
            item["file"] = item.get("file") or filename
            verified_vulns.append(item)

    # Append hallucinated dependencies to vulnerabilities as CRITICAL supply chain attacks
    for h in hallucinated_pkgs:
        h["language"] = language
        h["file"] = h.get("file") or filename
        verified_vulns.append(h)

    severity_counts = compute_severity_counts(verified_vulns)
    scan_time = round(time.time() - start_time, 2)

    # Identify primary model used
    models_used = {v.get("model_used") for v in verified_vulns if v.get("model_used")}
    primary_model = ", ".join(models_used) if models_used else "Ollama (qwen2.5-coder:7b)"

    summary = (
        f"Scan complete in {scan_time}s. Evaluated {filename} ({language}). "
        f"Found {len(verified_vulns)} vulnerabilities ({severity_counts['critical']} critical, "
        f"{severity_counts['high']} high, {severity_counts['medium']} medium, {severity_counts['low']} low)."
    )

    return {
        "filename": filename,
        "language": language,
        "vulnerabilities": verified_vulns,
        "hallucinated_packages": hallucinated_pkgs,
        "severity_counts": severity_counts,
        "files_scanned": 1,
        "files_skipped": [],
        "summary": summary,
        "primary_model": primary_model,
        "scan_time_seconds": scan_time
    }
