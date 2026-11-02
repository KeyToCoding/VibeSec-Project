"""
VibeSec Prompt Templates for AI Vulnerability Analysis, Web Security Assessment,
and Dependency Hallucination Verification.
Author: Kartikey Vishwakarma (NIELIT Gorakhpur Major Project)
"""

VULN_ANALYSIS_PROMPT = """You are an elite security researcher. Analyze this code for vulnerabilities.
Code: {code}
Language: {language}
Context: {context}
Semgrep finding: {semgrep_finding}

Respond ONLY in this exact JSON:
{{
  "is_vulnerable": true,
  "title": "short vulnerability name",
  "severity": "critical",
  "owasp": "OWASP category e.g. A03:2021",
  "description": "what the vulnerability is",
  "attack_scenario": "how an attacker would exploit this",
  "line_hint": 1,
  "confidence": "high",
  "fix": "exact fixed code or clear instruction"
}}
"""

URL_SECURITY_PROMPT = """You are a web security expert. Analyze these HTTP security headers and JS code.
Headers: {headers}
Cookies: {cookies}
Issues found: {issues}

Respond ONLY in this exact JSON format:
{{
  "assessment": "high-level summary of the web security posture",
  "missing_headers": ["list of crucial missing security headers"],
  "cookie_vulnerabilities": ["issues with cookie flags like HttpOnly, Secure, SameSite"],
  "vulnerabilities": [
    {{
      "title": "vulnerability title",
      "severity": "critical/high/medium/low",
      "owasp": "e.g. A05:2021-Security Misconfiguration",
      "description": "detailed vulnerability description",
      "attack_scenario": "how an attacker exploits this configuration",
      "fix": "recommended server configuration or header fix"
    }}
  ]
}}
"""

HALLUCINATION_PROMPT = """This npm package '{package_name}' does not exist on the npm registry.
Explain in 2 sentences why this is a supply chain attack risk."""

PYPI_HALLUCINATION_PROMPT = """This Python package '{package_name}' does not exist on the PyPI registry.
Explain in 2 sentences why this is a supply chain attack risk."""
