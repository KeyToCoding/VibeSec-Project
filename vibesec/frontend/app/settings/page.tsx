"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ThemeToggle } from "../../components/ThemeToggle";
import { CookieBanner } from "../../components/CookieBanner";

export default function SettingsPage() {
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [model, setModel] = useState("qwen2.5-coder:7b");
  const [autoOpenBot, setAutoOpenBot] = useState(true);
  const [skipVendorDirs, setSkipVendorDirs] = useState(true);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[var(--bg-main)] text-[var(--text-primary)] p-4 md:p-10 font-sans transition-colors">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Navigation back and ThemeToggle */}
        <div className="flex items-center justify-between pb-4 border-b border-[var(--card-border)]">
          <Link
            href="/"
            className="px-3 py-1.5 rounded-lg bg-[var(--card-bg)] hover:bg-[var(--bg-main)] text-xs font-medium text-[var(--text-primary)] border border-[var(--card-border)] transition-colors"
          >
            ← Back to Dashboard
          </Link>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-[var(--text-secondary)] hidden sm:inline">
              Scanner Engine Configuration
            </span>
            <ThemeToggle />
          </div>
        </div>

        {/* Settings Form Container */}
        <form onSubmit={handleSave} className="space-y-6">
          {/* Section 1: AI Engine Configuration */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm space-y-4">
            <div className="pb-3 border-b border-[var(--card-border)] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xl">🤖</span>
                <h2 className="text-base font-bold text-[var(--text-primary)]">
                  Local AI Inference (Ollama)
                </h2>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-[var(--success)]/10 text-[var(--success)] border border-[var(--success)]/20 font-semibold">
                ACTIVE
              </span>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-[var(--text-secondary)] mb-1.5 font-medium">
                  Ollama Base API URL
                </label>
                <input
                  type="text"
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] focus:border-[var(--accent)] rounded-lg px-3.5 py-2 text-[var(--text-primary)] font-mono text-xs focus:outline-none transition-colors"
                  placeholder="http://localhost:11434"
                />
                <p className="text-[11px] text-[var(--text-secondary)] mt-1">
                  Default: http://localhost:11434 (must have CORS enabled for web calls)
                </p>
              </div>

              <div>
                <label className="block text-[var(--text-secondary)] mb-1.5 font-medium">
                  Primary Model Tag
                </label>
                <select
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] focus:border-[var(--accent)] rounded-lg px-3.5 py-2 text-[var(--text-primary)] font-mono text-xs focus:outline-none transition-colors cursor-pointer"
                >
                  <option value="qwen2.5-coder:7b">qwen2.5-coder:7b (Recommended, 4.7GB)</option>
                  <option value="qwen2.5-coder:1.5b">qwen2.5-coder:1.5b (Fastest, 1.0GB)</option>
                  <option value="codellama:7b">codellama:7b (Meta Code Llama)</option>
                  <option value="deepseek-coder:6.7b">deepseek-coder:6.7b</option>
                </select>
              </div>
            </div>
          </div>

          {/* Section 2: Scanning & Analysis Preferences */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm space-y-4">
            <div className="pb-3 border-b border-[var(--card-border)] flex items-center gap-2">
              <span className="text-xl">⚙️</span>
              <h2 className="text-base font-bold text-[var(--text-primary)]">
                Scanner & Assistant Preferences
              </h2>
            </div>

            <div className="space-y-3.5 text-xs">
              {/* Toggle row 1 */}
              <label className="flex items-center justify-between p-3 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)] cursor-pointer hover:border-[var(--accent)] transition-colors">
                <div>
                  <span className="font-semibold text-[var(--text-primary)] block">
                    Auto-Open AI Assistant on Vulnerability
                  </span>
                  <span className="text-[11px] text-[var(--text-secondary)] block mt-0.5">
                    Automatically expand the SecurityBot widget when High/Critical issues are found
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={autoOpenBot}
                  onChange={(e) => setAutoOpenBot(e.target.checked)}
                  className="w-4 h-4 rounded accent-[var(--accent)] cursor-pointer ml-3"
                />
              </label>

              {/* Toggle row 2 */}
              <label className="flex items-center justify-between p-3 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)] cursor-pointer hover:border-[var(--accent)] transition-colors">
                <div>
                  <span className="font-semibold text-[var(--text-primary)] block">
                    Exclude Vendor Directories
                  </span>
                  <span className="text-[11px] text-[var(--text-secondary)] block mt-0.5">
                    Skip node_modules, .git, .venv, and vendor directories during recursive archives
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={skipVendorDirs}
                  onChange={(e) => setSkipVendorDirs(e.target.checked)}
                  className="w-4 h-4 rounded accent-[var(--accent)] cursor-pointer ml-3"
                />
              </label>
            </div>
          </div>

          {/* Section 3: Project Metadata */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm space-y-3">
            <h3 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
              <span>🏛️</span>
              <span>Project Crediting & Environment</span>
            </h3>
            <div className="p-3.5 bg-[var(--bg-main)] rounded-lg border border-[var(--card-border)] text-[var(--text-secondary)] text-xs space-y-1">
              <strong className="text-[var(--text-primary)] block mb-1">
                NIELIT Gorakhpur Major Project 2026 · ISEA Phase 3
              </strong>
              <p>Author: Kartikey Vishwakarma</p>
              <p>Email: kartikeyvishwakarma28@gmail.com</p>
              <p>Stack: FastAPI • Next.js • Ollama • Semgrep • MongoDB • Tailwind CSS</p>
            </div>
          </div>

          {/* Action Button */}
          <div className="flex items-center justify-end gap-3 pt-2">
            {savedSuccess && (
              <span className="text-xs text-[var(--success)] font-medium">
                ✓ Preferences updated successfully!
              </span>
            )}
            <button
              type="submit"
              className="px-5 py-2.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              Save Configuration
            </button>
          </div>
        </form>
      </div>

      <CookieBanner />
    </div>
  );
}
