"""
VibeSec Vulnerability Agent
Performs deep contextual security audits on flagged code chunks using LLM reasoning.
Utilizes an in-memory MD5 cache to avoid re-evaluating identical code snippets.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import hashlib
import json
import logging
from typing import Dict, Any, Optional
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from models.llm_chain import call_llm
    from models.prompts import VULN_ANALYSIS_PROMPT
except ImportError:
    from ..models.llm_chain import call_llm
    from ..models.prompts import VULN_ANALYSIS_PROMPT

logger = logging.getLogger("vibesec.vuln_agent")

# MD5 cache: chunk_hash -> analyzed_dict
_CHUNK_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}


def _clean_json_str(raw: str) -> str:
    """Extract the first complete JSON object, allowing harmless surrounding text."""
    raw = (raw or "").strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        if len(lines) > 2 and lines[-1].strip() == "```":
            raw = "\n".join(lines[1:-1]).strip()

    start = raw.find("{")
    if start < 0:
        return raw

    # Decode only the first complete object; do not include trailing commentary.
    decoder = json.JSONDecoder()
    try:
        _value, end = decoder.raw_decode(raw[start:])
        return raw[start:start + end]
    except json.JSONDecodeError:
        return raw[start:]


def _static_fallback_result(
    finding: Dict[str, Any],
    snippet: str,
    rule_msg: str,
    rule_id: str,
    line_start: int,
    filename: str,
) -> Dict[str, Any]:
    """Preserve the deterministic static finding when AI verification fails."""
    severity = str(finding.get("severity", "medium")).lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "medium"
    return {
        "title": rule_id or "Potential Vulnerability",
        "severity": severity,
        "owasp": "A03:2021-Injection",
        "description": rule_msg or "Static analysis detected a security pattern requiring review.",
        "attack_scenario": "An attacker may exploit the flagged input or unsafe operation if it is reachable.",
        "line_hint": line_start,
        "confidence": "medium",
        "fix": "Review the flagged operation and use a context-appropriate safe API or parameterized input.",
        "code_snippet": snippet,
        "file": filename,
        "model_used": "Static analysis (AI verification unavailable)",
        "rule_id": rule_id,
    }


async def analyze_chunk(
    finding: Dict[str, Any],
    code: str,
    language: str,
    filename: str = "inline"
) -> Optional[Dict[str, Any]]:
    """
    Perform deep LLM analysis of a static finding within its code context.
    Filters out low-confidence findings and false positives.
    """
    snippet = finding.get("code_snippet", "")
    rule_msg = finding.get("message", "")
    rule_id = finding.get("rule_id", "")
    line_start = finding.get("line_start", 1)

    # Compute cache key from snippet + rule
    cache_key = hashlib.md5(f"{language}:{snippet}:{rule_id}".encode("utf-8")).hexdigest()
    if cache_key in _CHUNK_CACHE:
        cached = _CHUNK_CACHE[cache_key]
        if cached:
            # Return copy with localized filename & line
            result = dict(cached)
            result["file"] = filename
            result["line_start"] = line_start
            return result
        return None

    # Construct LLM prompt
    prompt = VULN_ANALYSIS_PROMPT.format(
        code=snippet or code[:1500],
        language=language,
        context=f"File: {filename}, Lines {line_start} to {finding.get('line_end', line_start)}",
        semgrep_finding=f"[{finding.get('severity', 'HIGH')}] {rule_id}: {rule_msg}"
    )

    try:
        raw_output, model_used = await call_llm(prompt, task="chunk_analysis")
        clean_json = _clean_json_str(raw_output)
        data = json.loads(clean_json)
        if not isinstance(data, dict):
            raise ValueError("AI response was not a JSON object.")
        if not isinstance(data.get("is_vulnerable"), bool):
            raise ValueError("AI response is missing a boolean is_vulnerable field.")

        is_vulnerable = data["is_vulnerable"]
        confidence = str(data.get("confidence", "medium")).lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"

        # Filter: only accept if is_vulnerable is True and confidence != 'low'
        if is_vulnerable and confidence != "low":
            parsed_result = {
                "title": data.get("title", finding.get("rule_id", "Security Vulnerability")),
                "severity": (
                    str(data.get("severity", finding.get("severity", "medium"))).lower()
                    if str(data.get("severity", finding.get("severity", "medium"))).lower()
                    in {"critical", "high", "medium", "low"}
                    else str(finding.get("severity", "medium")).lower()
                ),
                "owasp": data.get("owasp", "A03:2021-Injection"),
                "description": data.get("description", rule_msg),
                "attack_scenario": data.get("attack_scenario", "Attacker can exploit input vector to manipulate execution."),
                "line_hint": data.get("line_hint", line_start),
                "confidence": confidence,
                "fix": data.get("fix", "Ensure strict input validation and use safe APIs."),
                "code_snippet": snippet,
                "file": filename,
                "model_used": model_used,
                "rule_id": rule_id
            }
            _CHUNK_CACHE[cache_key] = parsed_result
            return parsed_result
        else:
            logger.info(f"Finding {rule_id} dismissed by AI: is_vuln={is_vulnerable}, confidence={confidence}")
            _CHUNK_CACHE[cache_key] = None
            return None

    except json.JSONDecodeError as e:
        logger.warning(
            "AI returned malformed JSON for rule %s (%s); preserving the static finding.",
            rule_id,
            e.msg,
        )
        fallback = _static_fallback_result(finding, snippet, rule_msg, rule_id, line_start, filename)
        _CHUNK_CACHE[cache_key] = fallback
        return fallback
    except Exception as e:
        logger.warning(
            "AI verification failed for rule %s (%s); preserving the static finding.",
            rule_id,
            type(e).__name__,
        )
        fallback = _static_fallback_result(finding, snippet, rule_msg, rule_id, line_start, filename)
        _CHUNK_CACHE[cache_key] = fallback
        return fallback
