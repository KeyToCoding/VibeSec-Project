import os
import time
from playwright.sync_api import sync_playwright

OUTPUT_DIR = os.path.abspath("docs/presentation-assets")
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_URL = "http://localhost:3000"

print("Refining 09_ai_remediation_diff.png and 11_securitybot_conversation.png with completed responses...")

with sync_playwright() as p:
    browser = p.chromium.launch(
        executable_path=CHROME_PATH,
        headless=True
    )
    context = browser.new_context(
        viewport={"width": 1600, "height": 1000},
        device_scale_factor=1.5
    )
    context.add_init_script("""
        try {
            localStorage.setItem('vibesec-cookies', 'accepted');
        } catch(e) {}
    """)

    page = context.new_page()
    page.goto(BASE_URL, wait_until="networkidle")
    time.sleep(2)

    # 1. Run a fresh code scan
    print("Navigating to Scan...")
    page.locator("aside button:has-text('New Scan')").first.click()
    time.sleep(1)
    
    sqli_btn = page.locator("button:has-text('SQL Injection')").first
    if sqli_btn.is_visible():
        sqli_btn.click()
        time.sleep(0.5)

    scan_btn = page.locator("button:has-text('SCAN NOW')").first
    scan_btn.click()
    print("Running scan, waiting for verdict...")
    try:
        page.wait_for_selector("text=Security Assessment Verdict", timeout=50000)
    except Exception as e:
        print(f"Notice: {e}")
    time.sleep(2)

    # 2. Perfect AI Fix & Verify Modal (Waiting for complete patch generation)
    print("Opening AI Fix & Verify modal...")
    fix_btn = page.locator("button:has-text('AI Fix & Verify')").first
    if fix_btn.is_visible():
        fix_btn.click()
        time.sleep(1.5)
        gen_patch_btn = page.locator("button:has-text('Generate Secure Patch')").first
        if gen_patch_btn.is_visible():
            print("Clicking 'Generate Secure Patch'...")
            gen_patch_btn.click()
            print("Waiting for Ollama to synthesize unified git diff (up to 55s)...")
            
            for i in range(50):
                time.sleep(1)
                diff_btn = page.locator("button:has-text('Unified Diff')").first
                apply_btn = page.locator("button:has-text('Apply Fix to Editor')").first
                if apply_btn.is_visible() or diff_btn.is_visible():
                    print(f"Diff rendered after {i+1} seconds!")
                    break
            
            time.sleep(2)
            page.screenshot(path=os.path.join(OUTPUT_DIR, "09_ai_remediation_diff.png"))
            print("Saved perfected 09_ai_remediation_diff.png")

            # Close modal
            close_modal = page.locator("button:has-text('✕')").first
            if close_modal.is_visible():
                close_modal.click()
                time.sleep(1)

    # 3. Perfect SecurityBot Live Conversation (Waiting for full answer)
    print("Opening SecurityBot drawer...")
    bot_open = page.locator("input[placeholder*='vulnerability'], input[placeholder*='security question']").first.is_visible()
    if not bot_open:
        ask_ai = page.locator("header button:has-text('Ask AI')").first
        if ask_ai.is_visible():
            ask_ai.click()
        time.sleep(1.5)

    print("Triggering question: 'Show me secure code'...")
    sug_chip = page.locator("button:has-text('Show me secure code')").first
    if sug_chip.is_visible():
        sug_chip.click()
    else:
        chat_input = page.locator("input[placeholder*='vulnerability'], input[placeholder*='security question']").first
        chat_input.fill("How do I fix this SQL Injection vulnerability?")
        page.locator("button[type='submit']:has-text('Send')").first.click()

    print("Waiting for Ollama Qwen2.5-Coder to complete response...")
    # Poll until "Finalizing response" or "Thinking" disappears
    for i in range(50):
        time.sleep(1)
        finalizing = page.locator("text=Finalizing response").first.is_visible()
        if not finalizing and i > 15:
            print(f"SecurityBot finished response in {i+1} seconds!")
            break

    time.sleep(2)
    page.screenshot(path=os.path.join(OUTPUT_DIR, "11_securitybot_conversation.png"))
    print("Saved perfected 11_securitybot_conversation.png")

    browser.close()

print("Perfected screenshots updated successfully!")
