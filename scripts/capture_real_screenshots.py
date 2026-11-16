import os
import time
from playwright.sync_api import sync_playwright

OUTPUT_DIR = os.path.abspath("docs/presentation-assets")
os.makedirs(OUTPUT_DIR, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_URL = "http://localhost:3000"

print("=========================================================")
print("  VibeSec Real Browser Automated Screenshot Suite (v2)")
print("  Target: http://localhost:3000")
print("  Engine: Playwright with Google Chrome Headless")
print("  Output: docs/presentation-assets/")
print("=========================================================")

with sync_playwright() as p:
    browser = p.chromium.launch(
        executable_path=CHROME_PATH,
        headless=True
    )
    context = browser.new_context(
        viewport={"width": 1600, "height": 1000},
        device_scale_factor=1.5  # High-DPI crisp capture for presentation
    )
    # Pre-accept cookie consent so banner never intercepts clicks
    context.add_init_script("""
        try {
            localStorage.setItem('vibesec-cookies', 'accepted');
        } catch(e) {}
    """)

    page = context.new_page()

    # ----------------------------------------------------
    # 1. Main Dashboard
    # ----------------------------------------------------
    print("\n[1/13] Navigating to VibeSec Dashboard...")
    page.goto(BASE_URL, wait_until="networkidle")
    time.sleep(2)
    dash_btn = page.locator("aside button:has-text('Dashboard')").first
    if dash_btn.is_visible():
        dash_btn.click()
    page.evaluate("window.scrollTo(0, 0)")
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "01_dashboard.png"))
    print("  -> Captured: 01_dashboard.png")

    # ----------------------------------------------------
    # 2. Scanner - Code Mode
    # ----------------------------------------------------
    print("\n[2/13] Capturing Source Code Scanner...")
    scan_nav = page.locator("aside button:has-text('New Scan')").first
    if scan_nav.is_visible():
        scan_nav.click()
    time.sleep(1)
    
    code_tab = page.locator("#scan-panel button:has-text('Code'), button:has-text('Code')").first
    if code_tab.is_visible():
        code_tab.click()
    time.sleep(0.5)
    
    sqli_preset = page.locator("button:has-text('SQL Injection')").first
    if sqli_preset.is_visible():
        sqli_preset.click()
        time.sleep(0.5)

    page.locator("#scan-panel").scroll_into_view_if_needed()
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "02_scan_input_code.png"))
    print("  -> Captured: 02_scan_input_code.png")

    # ----------------------------------------------------
    # 3. Scanner - URL Mode
    # ----------------------------------------------------
    print("\n[3/13] Capturing URL Scanner...")
    url_tab = page.locator("#scan-panel button:has-text('URL'), button:has-text('URL')").first
    if url_tab.is_visible():
        url_tab.click()
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "03_scan_input_url.png"))
    print("  -> Captured: 03_scan_input_url.png")

    # ----------------------------------------------------
    # 4. Scanner - File Upload Mode
    # ----------------------------------------------------
    print("\n[4/13] Capturing File Upload Scanner...")
    upload_tab = page.locator("#scan-panel button:has-text('File'), button:has-text('File')").first
    if upload_tab.is_visible():
        upload_tab.click()
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "04_scan_input_upload.png"))
    print("  -> Captured: 04_scan_input_upload.png")

    # ----------------------------------------------------
    # 5. Scanner - GitHub Repo Mode
    # ----------------------------------------------------
    print("\n[5/13] Capturing GitHub Repository Scanner...")
    gh_tab = page.locator("#scan-panel button:has-text('GitHub'), button:has-text('GitHub')").first
    if gh_tab.is_visible():
        gh_tab.click()
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "05_scan_input_github.png"))
    print("  -> Captured: 05_scan_input_github.png")

    # ----------------------------------------------------
    # 6. Execute Scan & Capture Running Progress
    # ----------------------------------------------------
    print("\n[6/13] Triggering Scan & Capturing Running Progress...")
    code_tab.click()
    time.sleep(0.5)
    if sqli_preset.is_visible():
        sqli_preset.click()
        time.sleep(0.5)

    scan_btn = page.locator("button:has-text('SCAN NOW')").first
    scan_btn.click()
    time.sleep(0.8)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "06_scan_running_progress.png"))
    print("  -> Captured: 06_scan_running_progress.png")

    # ----------------------------------------------------
    # 7. Scan Results Overview
    # ----------------------------------------------------
    print("\n[7/13] Waiting for Scan Results Overview...")
    try:
        page.wait_for_selector("text=Security Assessment Verdict", timeout=50000)
    except Exception as e:
        print(f"  Notice: {e}")
    time.sleep(2)
    verdict_el = page.locator("text=Security Assessment Verdict").first
    if verdict_el.is_visible():
        verdict_el.scroll_into_view_if_needed()
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "07_scan_results_overview.png"))
    print("  -> Captured: 07_scan_results_overview.png")

    # ----------------------------------------------------
    # 8. Detailed Finding Card
    # ----------------------------------------------------
    print("\n[8/13] Capturing Finding Detail Card...")
    page.evaluate("window.scrollBy(0, 300)")
    time.sleep(1)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "08_finding_detail_expanded.png"))
    print("  -> Captured: 08_finding_detail_expanded.png")

    # ----------------------------------------------------
    # 9. AI Remediation Copilot Modal (Git Diff)
    # ----------------------------------------------------
    print("\n[9/13] Opening AI Fix & Verify Copilot Modal...")
    fix_btn = page.locator("button:has-text('AI Fix & Verify')").first
    if fix_btn.is_visible():
        fix_btn.click()
        time.sleep(1.5)
        gen_patch_btn = page.locator("button:has-text('Generate Secure Patch')").first
        if gen_patch_btn.is_visible():
            print("  Found 'Generate Secure Patch', initiating local Ollama reasoning...")
            gen_patch_btn.click()
            print("  Waiting up to 60s for patch generation and unified diff...")
            try:
                page.wait_for_selector("button:has-text('Apply Fix to Editor'), button:has-text('Unified Diff'), button:has-text('Verify Patch'), text=Proposed Patch", timeout=60000)
            except Exception as e:
                print(f"  Notice during patch wait: {e}")
            time.sleep(3)
        page.screenshot(path=os.path.join(OUTPUT_DIR, "09_ai_remediation_diff.png"))
        print("  -> Captured: 09_ai_remediation_diff.png")
        
        # Close modal
        close_modal = page.locator("button:has-text('✕')").first
        if close_modal.is_visible():
            close_modal.click()
            time.sleep(1)

    # ----------------------------------------------------
    # 10. SecurityBot Greeting
    # ----------------------------------------------------
    print("\n[10/13] Ensuring SecurityBot AI Assistant Drawer is Open...")
    bot_open = page.locator("input[placeholder*='vulnerability'], input[placeholder*='security question']").first.is_visible()
    if not bot_open:
        ask_ai = page.locator("header button:has-text('Ask AI')").first
        if ask_ai.is_visible():
            ask_ai.click()
        else:
            page.locator("aside button:has-text('AI Assistant')").first.click()
        time.sleep(1.5)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "10_securitybot_greeting.png"))
    print("  -> Captured: 10_securitybot_greeting.png")

    # ----------------------------------------------------
    # 11. SecurityBot Live Conversation
    # ----------------------------------------------------
    print("\n[11/13] Triggering SecurityBot Query & Waiting for Ollama Response...")
    # Click suggestion chip 'Show me secure code' or 'How to fix this?' if available
    sug_chip = page.locator("button:has-text('Show me secure code'), button:has-text('How to fix this?')").first
    if sug_chip.is_visible():
        print("  Clicking suggestion chip: 'Show me secure code'...")
        sug_chip.click()
    else:
        chat_input = page.locator("input[placeholder*='vulnerability'], input[placeholder*='security question']").first
        if chat_input.is_visible():
            chat_input.fill("How do I fix this SQL Injection vulnerability?")
            time.sleep(0.5)
            page.locator("button[type='submit']:has-text('Send')").first.click()
    
    print("  Waiting 35s for Qwen2.5-Coder response...")
    time.sleep(35)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "11_securitybot_conversation.png"))
    print("  -> Captured: 11_securitybot_conversation.png")
    
    # Close the chat drawer
    close_drawer = page.locator("button[title*='Close'], button:has-text('✕')").first
    if close_drawer.is_visible():
        close_drawer.click()
        time.sleep(1)

    # ----------------------------------------------------
    # 12. Scan History Tab
    # ----------------------------------------------------
    print("\n[12/13] Navigating to Scan History...")
    page.evaluate("window.scrollTo(0, 0)")
    hist_btn = page.locator("aside button:has-text('Scan History')").first
    if hist_btn.is_visible():
        hist_btn.click()
    time.sleep(2)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "12_scan_history.png"))
    print("  -> Captured: 12_scan_history.png")

    # ----------------------------------------------------
    # 13. Settings Tab / System Architecture
    # ----------------------------------------------------
    print("\n[13/13] Navigating to Settings / Architecture...")
    settings_btn = page.locator("aside button:has-text('Settings')").first
    if settings_btn.is_visible():
        settings_btn.click()
    time.sleep(2)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "13_settings_architecture.png"))
    print("  -> Captured: 13_settings_architecture.png")

    browser.close()

print("\n=========================================================")
print("  All 13 Real Screenshots Successfully Generated!")
print(f"  Directory: {OUTPUT_DIR}")
print("=========================================================")
