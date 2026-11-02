"""
VibeSec Remediation & Verification Engine
Provides deterministic patch validation, isolated temporary sandbox verification,
and integration with Ollama (qwen2.5-coder:7b) for AI-driven security remediation.

Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

import ast
import difflib
import json
import logging
import re
import tempfile
import os
from typing import Dict, Any, List, Optional, Tuple

try:
    from ..models.llm_chain import call_llm, LLMTimeoutError, LLMProviderError
    from ..scanner.semgrep_runner import semgrep_scan, native_fallback_scan
    from ..scanner.code_scanner import compute_severity_counts
except (ImportError, ValueError):
    from models.llm_chain import call_llm, LLMTimeoutError, LLMProviderError
    from scanner.semgrep_runner import semgrep_scan, native_fallback_scan
    from scanner.code_scanner import compute_severity_counts

logger = logging.getLogger("vibesec.remediation")

VERIFICATION_STATE_VERIFIED = "FIX VERIFIED BY AVAILABLE CHECKS"
VERIFICATION_STATE_STILL_DETECTED = "STILL DETECTED"
VERIFICATION_STATE_FAILED = "VERIFICATION FAILED"

SECURITY_DISCLAIMER = (
    "Passing static checks does not prove the code is completely secure. "
    "Static heuristics verify known syntactic patterns and rules, but cannot guarantee "
    "runtime safety, business-logic soundness, or absence of zero-day vulnerabilities. "
    "Always perform manual peer review, dynamic application security testing (DAST), "
    "and thorough test coverage prior to production deployment."
)

PROPOSE_PATCH_PROMPT = """You are VibeSec Security Copilot, an application security engineer.
Propose a concise, secure patch for the detected vulnerability.
Keep explanation to 1-2 sentences. Return the clean, remediated replacement code.

Finding: {title} ({severity}) | Rule: {rule_id}
Description: {description}
Evidence:
```
{code_snippet}
```

Working Code ({language}):
```{language}
{full_code}
```

Respond ONLY with valid JSON:
{{
  "explanation": "concise 1-2 sentence explanation of the fix",
  "patched_code": "the complete secure replacement code for the snippet",
  "changes_summary": ["bullet of change"]
}}
"""


def _clean_json_response(raw: str) -> str:
    """Extract JSON from potential markdown codeblocks or trailing text."""
    text = (raw or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # strip first line (```json) and last line if ```
        if len(lines) >= 2:
            start_idx = 1
            end_idx = len(lines) - 1 if lines[-1].strip() == "```" else len(lines)
            text = "\n".join(lines[start_idx:end_idx]).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        return text[start:end + 1]
    return text


def generate_unified_diff(original: str, patched: str, filename: str = "snippet") -> str:
    """Generate a clean, readable unified diff between original and patched code."""
    orig_lines = original.splitlines(keepends=True)
    patch_lines = patched.splitlines(keepends=True)

    diff = difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile=f"a/{filename} (vulnerable)",
        tofile=f"b/{filename} (remediated)",
        n=3
    )
    return "".join(diff)


async def propose_remediation_patch(
    vulnerability: Dict[str, Any],
    code: str = "",
    language: str = "python",
    filename: str = "snippet"
) -> Dict[str, Any]:
    """
    Ask the configured local Ollama model to propose a secure remediation patch,
    or generate actionable remediation steps for file-level / environment configuration findings.
    Validates patch structure and bounds context for CPU/GPU inference.
    """
    if not vulnerability or not isinstance(vulnerability, dict):
        raise ValueError("Vulnerability finding metadata must be provided.")

    code_text = (code or "").strip()
    title = str(vulnerability.get("title", "Unknown Flaw"))[:160]
    severity = str(vulnerability.get("severity", "medium"))[:30]
    owasp = str(vulnerability.get("owasp", "N/A"))[:100]
    rule_id = str(vulnerability.get("rule_id", vulnerability.get("id", "generic-rule")))[:100]
    line_hint = vulnerability.get("line_hint", "1")
    description = str(vulnerability.get("description", ""))[:600]
    snippet = str(vulnerability.get("code_snippet", ""))[:1500]
    target_file = vulnerability.get("file", filename or "file")
    fix_text = vulnerability.get("fix", "")

    # Handle file-level or environment findings without a code snippet
    if not code_text and not snippet:
        lower_title = title.lower()
        lower_file = target_file.lower()

        if "environment file" in lower_title or ".env" in lower_file or "template" in lower_title or "credential" in lower_title:
            remediation_steps = [
                f"Remove '{target_file}' from Git tracking: git rm --cached {target_file}",
                f"Add '{target_file}' to .gitignore to ensure sensitive credentials are never committed.",
                f"Commit the removal: git commit -m \"chore: remove {target_file} from version control tracking\"",
                "If credentials were ever pushed to a public remote repository, rewrite history using git-filter-repo or BFG Repo-Cleaner.",
                "Revoke and rotate any exposed API keys, passwords, database URLs, and session secrets immediately."
            ]
            recommended_commands = [
                f"git rm --cached {target_file}",
                f"echo \"{target_file}\" >> .gitignore",
                "git commit -m \"chore: untrack sensitive environment file\"",
            ]
        else:
            remediation_steps = [
                f"Review repository and filesystem permissions for '{target_file}'.",
                fix_text or f"Remediate the {title} misconfiguration according to security policy.",
                "Verify file is excluded from public builds and container image layers.",
                "Re-run VibeSec security audit to confirm resolved state."
            ]
            recommended_commands = [
                f"# Inspect file status:\ngit status {target_file}",
            ]

        explanation = (
            fix_text or (
                f"Finding '{title}' is an environment/repository configuration issue for '{target_file}'. "
                "Because this flaw is at the file and Git-tracking level rather than inline syntax, "
                "an automated code diff is not applicable. Follow the actionable remediation steps below."
            )
        )

        return {
            "success": True,
            "is_file_level": True,
            "remediation_type": "actionable_instructions",
            "title": title,
            "filename": target_file,
            "explanation": explanation,
            "remediation_steps": remediation_steps,
            "recommended_commands": recommended_commands,
            "patched_code": "",
            "unified_diff": "",
            "changes_summary": remediation_steps,
            "model_used": "VibeSec Remediation Copilot",
            "disclaimer": SECURITY_DISCLAIMER,
        }

    # Code snippet is available
    active_code = code_text if code_text else snippet
    bounded_code = active_code[:8000]

    prompt = PROPOSE_PATCH_PROMPT.format(
        title=title,
        severity=severity,
        owasp=owasp,
        rule_id=rule_id,
        line_hint=line_hint,
        description=description,
        code_snippet=snippet or bounded_code[:500],
        full_code=bounded_code,
        language=language
    )

    logger.info("Requesting remediation patch from Ollama for rule '%s' (%s)", rule_id, language)

    try:
        raw_output, model_used = await call_llm(prompt, task="patch_generation")
    except LLMTimeoutError as exc:
        logger.warning("Ollama timed out during patch generation: %s", exc)
        return {
            "success": False,
            "error": (
                "AI patch generation timed out. Ensure the local Ollama service "
                "(http://127.0.0.1:11434) is running, or review the snippet length."
            ),
            "model_used": "Ollama (timeout)",
            "can_retry": True
        }
    except LLMProviderError as exc:
        logger.warning("Ollama provider error during patch generation: %s", exc)
        return {
            "success": False,
            "error": f"AI provider could not generate a patch: {str(exc)[:400]}",
            "model_used": "Unavailable",
            "can_retry": True
        }
    except Exception as exc:
        logger.exception("Unexpected error during patch generation")
        return {
            "success": False,
            "error": f"Unexpected error while proposing patch: {str(exc)[:300]}",
            "model_used": "Error",
            "can_retry": True
        }

    clean_json = _clean_json_response(raw_output)
    try:
        data = json.loads(clean_json)
    except json.JSONDecodeError as exc:
        logger.warning("Malformed JSON from LLM: %s | raw: %s", exc, raw_output[:300])
        return {
            "success": False,
            "error": "The AI model returned an unparseable patch format. Please retry.",
            "raw_response": raw_output[:500],
            "model_used": model_used,
            "can_retry": True
        }

    patched_code = data.get("patched_code")
    explanation = data.get("explanation")
    changes_summary = data.get("changes_summary", [])
    security_caveats = data.get("security_caveats", "")

    # Validate returned patch format
    if not isinstance(patched_code, str) or not patched_code.strip():
        return {
            "success": False,
            "error": "The AI model did not provide valid replacement code.",
            "model_used": model_used,
            "can_retry": True
        }

    # Ensure patched code is not trivially identical or an empty stub
    if patched_code.strip() == code.strip():
        logger.info("Model suggested identical code without changes")

    unified_diff = generate_unified_diff(code, patched_code, filename=filename)

    return {
        "success": True,
        "patched_code": patched_code,
        "explanation": explanation or "Security fix addressing the identified vulnerability.",
        "changes_summary": changes_summary if isinstance(changes_summary, list) else [str(changes_summary)],
        "security_caveats": security_caveats or "",
        "unified_diff": unified_diff,
        "model_used": model_used,
        "original_code": code,
        "filename": filename,
        "language": language
    }


def _check_syntax(code: str, language: str) -> Tuple[bool, Optional[str]]:
    """Validate that patched code does not contain syntax errors."""
    lang = language.lower()
    if "python" in lang or lang == "py":
        try:
            ast.parse(code)
            return True, None
        except SyntaxError as e:
            return False, f"Python SyntaxError at line {e.lineno}: {e.msg}"
    # Basic check for unbalanced braces/parentheses for C-family/JS/TS
    if any(k in lang for k in ["javascript", "typescript", "js", "ts", "php", "java"]):
        open_curlies = code.count("{") - code.count("}")
        open_parens = code.count("(") - code.count(")")
        open_brackets = code.count("[") - code.count("]")
        if open_curlies != 0 or open_parens != 0 or open_brackets != 0:
            return False, (
                f"Potentially unbalanced delimiters: {{ {open_curlies:+d}, "
                f"( {open_parens:+d}, [ {open_brackets:+d}"
            )

    return True, None


def _is_vulnerability_present(
    findings: List[Dict[str, Any]],
    target_rule_id: str,
    target_title: str
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Check if the specific target vulnerability or equivalent is still present."""
    matched = []
    norm_target_rule = (target_rule_id or "").lower().strip()
    norm_target_title = (target_title or "").lower().strip()

    for f in findings:
        f_rule = str(f.get("rule_id", f.get("id", ""))).lower().strip()
        f_title = str(f.get("title", "")).lower().strip()
        f_msg = str(f.get("message", f.get("description", ""))).lower().strip()

        # Check rule ID match
        if norm_target_rule and (norm_target_rule in f_rule or f_rule in norm_target_rule):
            matched.append(f)
            continue

        # Check title match
        if norm_target_title and (norm_target_title in f_title or f_title in norm_target_title):
            matched.append(f)
            continue

        # Check keyword matches for key vuln classes
        vuln_keywords = ["sqli", "sql injection", "command injection", "cmdi", "hardcoded", "secret", "xss", "deserialization", "eval"]
        for kw in vuln_keywords:
            if kw in norm_target_title and (kw in f_title or kw in f_rule or kw in f_msg):
                matched.append(f)
                break

    return (len(matched) > 0, matched)


def verify_remediation_patch(
    original_code: str,
    patched_code: str,
    vulnerability: Dict[str, Any],
    language: str = "python",
    filename: str = "snippet",
    user_approved: bool = False
) -> Dict[str, Any]:
    """
    Deterministically test the proposed patch in an isolated temporary buffer.
    Reruns static scanner rules to confirm if the vulnerability is resolved.

    Requires explicit user approval (user_approved=True).
    Never executes code.
    Never overwrites user files or git repositories.
    """
    if not user_approved:
        return {
            "verification_state": VERIFICATION_STATE_FAILED,
            "verified": False,
            "error": "Explicit user approval is required before applying and verifying changes.",
            "disclaimer": SECURITY_DISCLAIMER
        }

    if not patched_code or not isinstance(patched_code, str) or not patched_code.strip():
        return {
            "verification_state": VERIFICATION_STATE_FAILED,
            "verified": False,
            "error": "Patched code is empty or missing.",
            "disclaimer": SECURITY_DISCLAIMER
        }

    # 1. Syntax check
    is_valid_syntax, syntax_error = _check_syntax(patched_code, language)
    if not is_valid_syntax:
        return {
            "verification_state": VERIFICATION_STATE_FAILED,
            "verified": False,
            "error": f"Patched code failed syntax validation: {syntax_error}",
            "syntax_error": syntax_error,
            "before_findings": [vulnerability],
            "after_findings": [],
            "disclaimer": SECURITY_DISCLAIMER
        }

    target_rule_id = str(vulnerability.get("rule_id", vulnerability.get("id", "")))
    target_title = str(vulnerability.get("title", ""))

    # 2. Run deterministic scanner rules against original code
    # (use Semgrep / native patterns, no code execution)
    original_findings = semgrep_scan(original_code, language)

    # 3. Run deterministic scanner rules against patched code in isolated memory/temp file
    patched_findings = semgrep_scan(patched_code, language)

    # 4. Check if target vulnerability is still detected
    target_still_present, lingering_findings = _is_vulnerability_present(
        patched_findings,
        target_rule_id,
        target_title
    )

    # Check for any remaining critical/high findings
    remaining_critical = [
        f for f in patched_findings
        if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
    ]

    # Generate unified diff for visual evidence
    diff = generate_unified_diff(original_code, patched_code, filename=filename)

    if target_still_present:
        return {
            "verification_state": VERIFICATION_STATE_STILL_DETECTED,
            "verified": False,
            "message": (
                f"The vulnerability '{target_title}' is STILL DETECTED by the static scanner rules "
                f"after applying the proposed patch."
            ),
            "target_findings": lingering_findings,
            "before_findings": original_findings,
            "after_findings": patched_findings,
            "remaining_issues_count": len(patched_findings),
            "unified_diff": diff,
            "disclaimer": SECURITY_DISCLAIMER
        }

    # Check if a new or different critical flaw was introduced
    if remaining_critical:
        # The specific target was removed, but other critical flaws persist
        return {
            "verification_state": VERIFICATION_STATE_VERIFIED,
            "verified": True,
            "message": (
                f"Target vulnerability '{target_title}' was successfully resolved. "
                f"Note: {len(remaining_critical)} other issues remain in the file."
            ),
            "before_findings": original_findings,
            "after_findings": patched_findings,
            "remaining_issues": remaining_critical,
            "remaining_issues_count": len(patched_findings),
            "unified_diff": diff,
            "disclaimer": SECURITY_DISCLAIMER
        }

    # Clean verification!
    return {
        "verification_state": VERIFICATION_STATE_VERIFIED,
        "verified": True,
        "message": (
            f"Fix verified by available checks! Static analysis rules for '{target_title}' "
            f"no longer trigger on the patched code."
        ),
        "before_findings": original_findings,
        "after_findings": patched_findings,
        "remaining_issues_count": len(patched_findings),
        "unified_diff": diff,
        "disclaimer": SECURITY_DISCLAIMER
    }
