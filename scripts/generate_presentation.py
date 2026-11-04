import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_vibesec_presentation():
    prs = Presentation()
    # 16:9 widescreen
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    blank_layout = prs.slide_layouts[6]

    # Color Palette (Dark Cybersecurity Theme)
    BG_COLOR = RGBColor(11, 15, 25)         # #0B0F19 Dark Navy
    CARD_COLOR = RGBColor(22, 30, 46)       # #161E2E Slate Card
    TEXT_MAIN = RGBColor(249, 250, 251)     # #F9FAFB Clean White
    TEXT_MUTED = RGBColor(156, 163, 175)    # #9CA3AF Silver
    CYAN_ACCENT = RGBColor(6, 182, 212)     # #06B6D4 Electric Cyan
    GREEN_ACCENT = RGBColor(16, 185, 129)   # #10B981 Emerald
    AMBER_ACCENT = RGBColor(245, 158, 11)   # #F59E0B Amber
    RED_ACCENT = RGBColor(239, 68, 68)      # #EF4444 Crimson

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.fill.background() # No border
        return bg

    def add_header(slide, title_text, category_text="VIBESEC MAJOR PROJECT"):
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = CYAN_ACCENT

        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.5), Inches(0.8))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(26)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_MAIN

    def add_card(slide, left, top, width, height, title="", items=None, accent=CYAN_ACCENT):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_COLOR
        card.line.color.rgb = accent
        card.line.width = Pt(1)

        tb = slide.shapes.add_textbox(Inches(left + 0.25), Inches(top + 0.2), Inches(width - 0.5), Inches(height - 0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        if title:
            p_head = tf.paragraphs[0]
            p_head.text = title
            p_head.font.size = Pt(16)
            p_head.font.bold = True
            p_head.font.color.rgb = accent
            p_head.space_after = Pt(8)

        if items:
            for idx, item in enumerate(items):
                p = tf.add_paragraph() if (title or idx > 0) else tf.paragraphs[0]
                p.text = f"•  {item}"
                p.font.size = Pt(12)
                p.font.color.rgb = TEXT_MAIN
                p.space_after = Pt(6)

    # ==================== SLIDE 1: Title Slide ====================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    t_box = s1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(3.5))
    tf1 = t_box.text_frame
    tf1.word_wrap = True

    p0 = tf1.paragraphs[0]
    p0.text = "NIELIT GORAKHPUR  |  MAJOR PROJECT TECHNICAL DEFENSE"
    p0.font.size = Pt(13)
    p0.font.bold = True
    p0.font.color.rgb = CYAN_ACCENT
    p0.space_after = Pt(12)

    p1 = tf1.add_paragraph()
    p1.text = "VibeSec: AI-Powered Application Security Scanner"
    p1.font.size = Pt(36)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_MAIN
    p1.space_after = Pt(8)

    p2 = tf1.add_paragraph()
    p2.text = "Privacy-First Static Application Security Testing (SAST) & AI Remediation Copilot for Modern Codebases"
    p2.font.size = Pt(17)
    p2.font.color.rgb = TEXT_MUTED
    p2.space_after = Pt(24)

    p3 = tf1.add_paragraph()
    p3.text = "Candidate: Kartikey Vishwakarma   •   Repository: github.com/KeyToCoding/VibeSec-Project   •   Date: November 2026"
    p3.font.size = Pt(12)
    p3.font.color.rgb = GREEN_ACCENT

    # ==================== SLIDE 2: Problem Definition ====================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "The Critical Security Dilemma in AI-Generated Code", "PROBLEM & MOTIVATION")

    add_card(s2, 0.8, 1.8, 3.6, 5.0, "Silent Vulnerabilities", [
        "LLMs (GitHub Copilot, ChatGPT) write code to maximize likelihood, not security posture.",
        "Over 40% of generated snippets harbor critical flaws: SQL Injection, Command Injection, and Path Traversal.",
        "Lack of perimeter context leads to insecure deserialization and weak cryptography."
    ], RED_ACCENT)

    add_card(s2, 4.8, 1.8, 3.6, 5.0, "Dependency Hallucination", [
        "AI models frequently hallucinate plausible-sounding npm and PyPI package names.",
        "Attackers exploit this via 'slopsquatting': registering fake packages with malicious payloads.",
        "Conventional linters fail to verify whether imported packages genuinely exist on registries."
    ], AMBER_ACCENT)

    add_card(s2, 8.8, 1.8, 3.6, 5.0, "The Cloud Privacy Gap", [
        "Cloud-based security scanners transmit proprietary source code to external AI vendors.",
        "Leaks intellectual property, API keys, and confidential database schemas.",
        "High API token costs and non-compliance with strict data localization laws (SOC2, GDPR)."
    ], CYAN_ACCENT)

    # ==================== SLIDE 3: The VibeSec Solution ====================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "The VibeSec Solution: Privacy-First Hybrid Defense", "CORE INNOVATION")

    add_card(s3, 0.8, 1.8, 5.6, 2.4, "100% Local Inference Privacy", [
        "Powered by local Qwen2.5-Coder:7B hosted on-premises via Ollama.",
        "Zero proprietary source code or credentials leave the developer's workstation.",
        "Eliminates third-party API dependencies and recurring cloud token costs."
    ], GREEN_ACCENT)

    add_card(s3, 6.8, 1.8, 5.6, 2.4, "Dual-Engine Hybrid SAST", [
        "Stage 1: High-speed deterministic AST parsing and Semgrep pattern detection.",
        "Stage 2: Context-grounded LLM verification filtering benign false positives.",
        "Sub-second analysis for snippets; comprehensive scans for full repositories."
    ], CYAN_ACCENT)

    add_card(s3, 0.8, 4.5, 5.6, 2.4, "Real-Time Registry Verification", [
        "Active AST dependency parsing across package.json and requirements.txt.",
        "Live HTTP queries against official npm and PyPI registries to catch slopsquatting.",
        "Flagged supply chain risks are instantly highlighted before deployment."
    ], AMBER_ACCENT)

    add_card(s3, 6.8, 4.5, 5.6, 2.4, "AI Remediation Copilot", [
        "Generates syntactically correct unified git diffs adhering strictly to code indentation.",
        "Automated sandbox re-scanning verifies vulnerability elimination before developer approval.",
        "Transforms passive vulnerability reporting into proactive, verified resolution."
    ], GREEN_ACCENT)

    # ==================== SLIDE 4: Architecture ====================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "3-Tier Distributed System Architecture", "SYSTEM ARCHITECTURE")

    add_card(s4, 0.8, 1.8, 3.6, 5.0, "Frontend Client Tier", [
        "React 18 + TypeScript + Vite + Tailwind CSS.",
        "Modern Bugcrowd-style cybersecurity interface.",
        "Interactive vulnerability inspector, diff viewer, and real-time history filters.",
        "Embedded SecurityBot assistant with Markdown syntax highlighting & code copying."
    ], CYAN_ACCENT)

    add_card(s4, 4.8, 1.8, 3.6, 5.0, "Gateway & Core Backend", [
        "Express.js API Gateway (Port 3000): Serves assets, handles routing, and enforces 165s timeout.",
        "FastAPI Python 3.11 Backend (Port 8000): High-performance asynchronous REST microservice.",
        "Cryptographic HMAC-SHA256 session token generation and session report isolation.",
        "MongoDB with automatic In-Memory fallback for zero-configuration portability."
    ], GREEN_ACCENT)

    add_card(s4, 8.8, 1.8, 3.6, 5.0, "Local AI & Tunnel Subsystem", [
        "Ollama Daemon (Port 11434): Qwen2.5-Coder:7B optimized for software security.",
        "Authenticated Reverse Proxy (Port 11435): Validates internal Bearer tokens to protect compute.",
        "Cloudflare Secure Tunnel: Optional zero-trust external connectivity for remote evaluations.",
        "Synchronized 130s inference read boundary preventing server stalls."
    ], AMBER_ACCENT)

    # ==================== SLIDE 5: Functional Capabilities ====================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Six Core Functional Modules", "FUNCTIONAL CAPABILITIES")

    add_card(s5, 0.8, 1.8, 3.6, 2.4, "1. Code Scanner", [
        "Multi-language AST parser for Python, JS, TS, PHP, Java, and Go.",
        "Identifies SQLi, Command Injection, and secrets.",
        "Sub-second analysis with line-level hints."
    ], CYAN_ACCENT)

    add_card(s5, 4.8, 1.8, 3.6, 2.4, "2. Web Security Auditor", [
        "Audits HTTP headers: CSP, HSTS, X-Frame.",
        "Evaluates cookie flags: HttpOnly, Secure, SameSite.",
        "TLS configuration and endpoint posture scoring."
    ], CYAN_ACCENT)

    add_card(s5, 8.8, 1.8, 3.6, 2.4, "3. Archive Upload Scanner", [
        "Multi-file ZIP and tar.gz project ingestion.",
        "Strict 100MB upload limit and 100-file quota.",
        "Anti-Zip-Bomb (250MB) and Zip-Slip traversal defense."
    ], GREEN_ACCENT)

    add_card(s5, 0.8, 4.5, 3.6, 2.4, "4. GitHub Repo Scanner", [
        "Public repo auditing via GitHub REST API.",
        "Auto-ignores vendor trees (node_modules, vendor).",
        "Parallel source downloading and bulk vulnerability triage."
    ], GREEN_ACCENT)

    add_card(s5, 4.8, 4.5, 3.6, 2.4, "5. AI Remediation Copilot", [
        "Synthesizes unified git diffs for verified fixes.",
        "Preserves indentation and surrounding business logic.",
        "Sandbox re-scan verifies vulnerability elimination."
    ], AMBER_ACCENT)

    add_card(s5, 8.8, 4.5, 3.6, 2.4, "6. Interactive SecurityBot", [
        "Session-grounded conversational security guidance.",
        "Deep context passing from detected scan findings.",
        "Formatted markdown, bullet points, and code copy blocks."
    ], AMBER_ACCENT)

    # ==================== SLIDE 6: Hybrid Scanning ====================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Two-Stage Hybrid Scanning Methodology", "METHODOLOGY")

    add_card(s6, 0.8, 1.8, 5.6, 5.0, "Stage 1: Deterministic Heuristic SAST", [
        "Fast syntactic and pattern recognition powered by Semgrep and regex engine.",
        "Audits code against curated rules: vibesec.sqli, vibesec.cmdi, vibesec.secrets.",
        "Flags candidate vulnerabilities with precise file path, line hint, and raw code snippet.",
        "Processes thousands of lines per second without invoking compute-heavy neural nets.",
        "Guarantees 100% recall on known syntactical vulnerability signatures."
    ], CYAN_ACCENT)

    add_card(s6, 6.8, 1.8, 5.6, 5.0, "Stage 2: Context-Aware LLM Verification", [
        "Candidate findings are dispatched to Qwen2.5-Coder:7B with strict JSON schemas.",
        "The model analyzes surrounding control flow to verify exploitability.",
        "Filters benign false positives (e.g., hardcoded mock data, test fixtures, sanitized inputs).",
        "Assigns confidence scores (High, Medium, Low) and generates realistic attack scenarios.",
        "Outputs concise, actionable remediation advice for developers."
    ], GREEN_ACCENT)

    # ==================== SLIDE 7: Package Hallucination ====================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Neutralizing Package Hallucination & Supply Chain Risks", "DEPENDENCY SECURITY")

    add_card(s7, 0.8, 1.8, 5.6, 5.0, "The Hallucination Threat Model", [
        "Generative AI models hallucinate plausible libraries (e.g., 'express-jwt-guard').",
        "Developers copy-paste requirements directly into production environments.",
        "Adversaries register hallucinated names on public registries ('slopsquatting').",
        "Malicious packages execute pre-install scripts stealing environment variables and tokens.",
        "Traditional SAST tools do not cross-reference registry availability."
    ], RED_ACCENT)

    add_card(s7, 6.8, 1.8, 5.6, 5.0, "The VibeSec Registry Verification Engine", [
        "Parses package manifests (package.json, requirements.txt) and source import statements.",
        "Extracts canonical package names, stripping internal relative modules and stdlib packages.",
        "Queries live registry APIs: https://registry.npmjs.org and https://pypi.org/pypi.",
        "Caches negative registry responses (HTTP 404) with backoff retry logic.",
        "Immediate CRITICAL alert triggers when an imported package does not exist."
    ], GREEN_ACCENT)

    # ==================== SLIDE 8: Security & Defense-in-Depth ====================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Architectural Defense-in-Depth Controls", "APPLICATION HARDENING")

    add_card(s8, 0.8, 1.8, 3.6, 5.0, "Cryptographic Sessions", [
        "HMAC-SHA256 session token generation: session_id.signature.",
        "Client X-Session-ID headers validated against cryptographic signatures.",
        "Strict multi-tenant scan report and history isolation.",
        "Unauthenticated or forged tokens trigger HTTP 401/403."
    ], GREEN_ACCENT)

    add_card(s8, 4.8, 1.8, 3.6, 5.0, "Archive Upload Armor", [
        "Zip-Slip Prevention: Validates target paths stay inside sandbox using os.path.commonpath.",
        "Zip-Bomb Defense: Hard ceiling of 250MB total uncompressed extraction bytes.",
        "Request Size Quota: Rejects any upload payload exceeding 100MB before disk spooling.",
        "File Count Limit: Caps multi-file archives at 100 files to prevent resource exhaustion."
    ], AMBER_ACCENT)

    add_card(s8, 8.8, 1.8, 3.6, 5.0, "Protected AI Proxy", [
        "Custom lightweight proxy (scripts/ollama_proxy.py) sits in front of Ollama.",
        "Enforces internal Bearer Token authentication on all incoming requests.",
        "Shields Ollama daemon from unauthorized compute theft over public Cloudflare tunnels.",
        "Separates local development loopback from external ingress points."
    ], CYAN_ACCENT)

    # ==================== SLIDE 9: Coordinated Timeouts ====================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Eliminating Client 'Failed to Fetch': Coordinated Timeout Stack", "PERFORMANCE")

    add_card(s9, 0.8, 1.8, 11.6, 5.0, "Synchronized Timeout Hierarchy Across the Application Stack", [
        "1. React SecurityBot Client (175s): AbortController deadline ensures browser never drops fetch before downstream finishes.",
        "2. Express API Gateway Proxy (165s): 20s buffer above backend handles network streaming and HTTP proxy buffering.",
        "3. FastAPI Python Backend (145s): 15s margin above Ollama ensures clean JSON serialization and database storage.",
        "4. Ollama HTTP Client (130s): Bounds maximum time waiting for CPU-based model token generation.",
        "5. Output Token Ceiling (384 tokens): Keeps responses bounded (80–140 words); normal queries complete in 25–40s with done_reason='stop'.",
        "6. Bounded Continuation Recovery: Automatic stitching handles occasional length boundaries; code blocks automatically close."
    ], CYAN_ACCENT)

    # ==================== SLIDE 10: UI Progression ====================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Intuitive Developer Experience & UI Flow", "USER INTERFACE")

    add_card(s10, 0.8, 1.8, 5.6, 2.4, "Executive Security Dashboard", [
        "Real-time vulnerability distributions (Critical, High, Medium, Low).",
        "Active AI model health indicator and connectivity diagnostics.",
        "Instant launchpad for Code, URL, Upload, and GitHub scans."
    ], CYAN_ACCENT)

    add_card(s10, 6.8, 1.8, 5.6, 2.4, "Interactive Code & Finding Audit", [
        "Syntax-highlighted code editor with line numbers and multi-language support.",
        "Vulnerability cards mapped directly to OWASP Top 10 standards.",
        "Realistic attack scenarios and one-click 'Ask AI' context handoff."
    ], GREEN_ACCENT)

    add_card(s10, 0.8, 4.5, 5.6, 2.4, "AI Remediation Diff Modal", [
        "Side-by-side and unified git diff visualization of suggested fixes.",
        "Preserves original indentation, formatting, and surrounding scope.",
        "Developer-approved sandbox verification before accepting code."
    ], AMBER_ACCENT)

    add_card(s10, 6.8, 4.5, 5.6, 2.4, "Conversational SecurityBot", [
        "Slide-out cyber-defense assistant powered by local Ollama.",
        "One-click suggestion chips: OWASP Top 10, SQLi Fixes, Testing Tips.",
        "Markdown rendering with inline code and copy-to-clipboard buttons."
    ], CYAN_ACCENT)

    # ==================== SLIDE 11: Unit Test Suite ====================
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "Comprehensive Quality Assurance: 82/82 Unit Tests Passed", "TEST METRICS")

    add_card(s11, 0.8, 1.8, 5.6, 5.0, "Backend Unit Test Execution (55.38s)", [
        "test_api_endpoints.py (14 tests): Access control, token validation, session isolation.",
        "test_defect_resolutions.py (18 tests): DEF-001 to DEF-014 bug resolution verification.",
        "test_env_detector.py (12 tests): Secret scanning across .env files, API keys, passwords.",
        "test_github_scanner.py (11 tests): URL parsing, rate limiting, tree extraction.",
        "test_ollama_provider.py (9 tests): Prompt generation, proxy headers, fallback cascades.",
        "test_remediation.py (8 tests): Diff synthesis, patch structure, sandbox verification.",
        "test_upload_limits.py (10 tests): 100MB limit, Zip-Bomb ceiling, Zip-Slip traversal defense."
    ], GREEN_ACCENT)

    add_card(s11, 6.8, 1.8, 5.6, 5.0, "Frontend & Build Quality Metrics", [
        "TypeScript Compilation: npx tsc --noEmit executed with 0 type errors.",
        "Production Bundle Build: npm run build completed cleanly in 732ms.",
        "Asset Optimization: index.js (353 kB), index.css (57.8 kB), index.html (1.4 kB).",
        "Clean Git Audit: Zero trailing whitespace warnings, zero CRLF anomalies.",
        "Zero Secret Leakage: .env*, .proxy_token, and .venv strictly excluded by .gitignore.",
        "Verified Portable Execution on clean Windows 10/11 environments."
    ], CYAN_ACCENT)

    # ==================== SLIDE 12: Real-World GitHub Scans ====================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Empirical Validation: Live GitHub Repository Scans", "BENCHMARK RESULTS")

    add_card(s12, 0.8, 1.8, 5.6, 5.0, "OWASP NodeGoat Benchmark", [
        "Target: https://github.com/OWASP/NodeGoat",
        "Scan Status: HTTP 200 OK  •  Elapsed Time: 54.65 seconds",
        "Audited 15 source files including Gruntfile.js, app.json, and raphael-min.js.",
        "Extracted tree recursively via public GitHub REST API without requiring PAT.",
        "Triggered candidate AST analysis and evaluated findings via local Ollama.",
        "Generated structured JSON security report with zero runtime crashes."
    ], GREEN_ACCENT)

    add_card(s12, 6.8, 1.8, 5.6, 5.0, "OWASP Juice Shop & Negative Tests", [
        "Target: https://github.com/juice-shop/juice-shop",
        "Scan Status: HTTP 200 OK  •  Elapsed Time: 9.90 seconds  •  Files: 15",
        "Negative Test 1 (Invalid URL): https://not-github.com/foo/bar",
        "-> HTTP 400 Bad Request: 'Could not parse owner/repo from URL'",
        "Negative Test 2 (Non-Existent Repo): KeyToCoding/Definitely-Not-Found-12345",
        "-> HTTP 404 Not Found: Friendly user guidance regarding public repo existence."
    ], CYAN_ACCENT)

    # ==================== SLIDE 13: Chatbot Benchmark ====================
    s13 = prs.slides.add_slide(blank_layout)
    set_slide_background(s13)
    add_header(s13, "Live Chatbot Reliability: 100% Completion & Zero Drift", "AI BENCHMARK")

    add_card(s13, 0.8, 1.8, 5.6, 2.4, "'What is SQL Injection?'", [
        "Status: 200 OK  •  Elapsed: 40.80s  •  Tokens: 126  •  Reason: stop",
        "Accurate risk and root cause explanation.",
        "Exact sqlite3 parameterized query example: cursor.execute(..., (user, pass)).",
        "Zero prompt drift; no unrelated password validation code."
    ], GREEN_ACCENT)

    add_card(s13, 6.8, 1.8, 5.6, 2.4, "'How do I prevent XSS?'", [
        "Status: 200 OK  •  Elapsed: 27.74s  •  Tokens: 117  •  Reason: stop",
        "Concise 3-point structured security explanation.",
        "Recommends input sanitization and contextual output encoding.",
        "Demonstrates encodeURIComponent() and escapeHTML() usage."
    ], GREEN_ACCENT)

    add_card(s13, 0.8, 4.5, 5.6, 2.4, "'Explain command injection in Python.'", [
        "Status: 200 OK  •  Elapsed: 39.44s  •  Tokens: 171  •  Reason: stop",
        "Explains risk of string concatenation in shell commands.",
        "Provides safe remediation using subprocess with arguments array and shell=False.",
        "Demonstrates subprocess.quote() for escaped inputs."
    ], CYAN_ACCENT)

    add_card(s13, 6.8, 4.5, 5.6, 2.4, "'Show a secure SQLite query.'", [
        "Status: 200 OK  •  Elapsed: 35.33s  •  Tokens: 152  •  Reason: stop",
        "Complete, runnable Python snippet with sqlite3 connection.",
        "Demonstrates SELECT * FROM users WHERE id = ? with (user_id,) tuple.",
        "All code fences (```) completely closed; zero truncation."
    ], CYAN_ACCENT)

    # ==================== SLIDE 14: Portability & Operations ====================
    s14 = prs.slides.add_slide(blank_layout)
    set_slide_background(s14)
    add_header(s14, "One-Click Setup, Portability & Operational Tooling", "OPERATIONS")

    add_card(s14, 0.8, 1.8, 5.6, 5.0, "Zero-Friction Developer Experience", [
        "One-Click VS Code Launch: Press Ctrl + Shift + B to start full stack.",
        "Automated background process management for FastAPI, Express, and Proxy.",
        "Dynamic port binding with loopback binding to prevent conflict.",
        "Automatic In-Memory fallback store eliminates hard MongoDB dependency.",
        "Self-contained local mode operates seamlessly without internet connection."
    ], GREEN_ACCENT)

    add_card(s14, 6.8, 1.8, 5.6, 5.0, "Automated PowerShell Maintenance Scripts", [
        "scripts/Repair-Venv.ps1: Automatically rebuilds Python 3.11 virtual environment.",
        "scripts/Show-Antigravity-Connection.ps1: Displays active URLs and tunnel health.",
        "scripts/Run-Antigravity-Tunnel.ps1: Manages Cloudflare tunnel ingress & tokens.",
        "scripts/Stop-VibeSec-All.ps1: Gracefully terminates processes releasing file locks.",
        "Pre-requisite check script verifies Node.js, Python, and Ollama versions."
    ], CYAN_ACCENT)

    # ==================== SLIDE 15: Conclusion & Future Work ====================
    s15 = prs.slides.add_slide(blank_layout)
    set_slide_background(s15)
    add_header(s15, "Project Conclusion & Future Roadmap", "CONCLUSION")

    add_card(s15, 0.8, 1.8, 5.6, 5.0, "Major Project Achievements", [
        "Engineered an enterprise-grade, privacy-first application security scanner.",
        "Successfully unified deterministic SAST heuristics with local Qwen2.5-Coder:7B.",
        "Resolved 14 engineering defects (DEF-001 to DEF-014) ensuring 100% test reliability.",
        "82/82 Backend Unit Tests passing, 4/4 live AI chatbot benchmarks verified.",
        "Production-ready deployment architecture supporting local and cloud environments.",
        "Full compliance with academic submission standards at NIELIT Gorakhpur."
    ], GREEN_ACCENT)

    add_card(s15, 6.8, 1.8, 5.6, 5.0, "Future Strategic Roadmap", [
        "Native IDE Extensions: Building official plugins for VS Code and JetBrains.",
        "CI/CD Pipeline Integration: Publishing a turnkey GitHub Action to gate PRs.",
        "Multi-Model Switching: Dynamic fallback to Llama-3-8B or DeepSeek-Coder.",
        "Automated SAST Rule Generation: AI-assisted creation of custom Semgrep patterns.",
        "Enterprise Dashboard: Multi-repository vulnerability trends and SLA analytics."
    ], CYAN_ACCENT)

    # Save presentation
    output_path = os.path.abspath("docs/VibeSec_Final_Project_Presentation.pptx")
    prs.save(output_path)
    print(f"Presentation saved successfully to: {output_path}")

if __name__ == "__main__":
    create_vibesec_presentation()
