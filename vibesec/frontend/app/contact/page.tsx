"use client";

import React from "react";
import Link from "next/link";
import { ThemeToggle } from "../../components/ThemeToggle";
import { CookieBanner } from "../../components/CookieBanner";

export default function ContactPage() {
  return (
    <div className="min-h-screen bg-[var(--bg-main)] text-[var(--text-primary)] p-4 md:p-10 font-sans transition-colors">
      <div className="max-w-4xl mx-auto space-y-8">
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
              NIELIT Gorakhpur Major Project · 2026
            </span>
            <ThemeToggle />
          </div>
        </div>

        {/* HEADER SECTION (BugCrowd executive profile card) */}
        <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-2xl p-6 sm:p-8 shadow-sm relative overflow-hidden flex flex-col sm:flex-row items-center sm:items-start gap-6 text-center sm:text-left transition-all">
          {/* Subtle glow accent background */}
          <div className="absolute top-0 right-0 w-64 h-64 bg-[var(--accent)]/5 rounded-full blur-3xl pointer-events-none"></div>

          {/* Avatar: "KV" initials circle */}
          <div className="w-24 h-24 rounded-2xl bg-gradient-to-tr from-[var(--accent)] to-amber-500 flex items-center justify-center font-extrabold text-3xl text-white shadow-md shrink-0 ring-2 ring-[var(--card-border)]">
            KV
          </div>

          <div className="space-y-2 flex-1">
            <div className="inline-block px-3 py-1 rounded-md text-[11px] font-mono font-bold bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/30 uppercase tracking-wider mb-1">
              Lead Architect & Researcher
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[var(--text-primary)] tracking-tight">
              Kartikey Vishwakarma
            </h1>
            <p className="text-sm font-medium text-[var(--success)] flex items-center justify-center sm:justify-start gap-2">
              <span>🛡️</span>
              <span>Security Intern — ISEA Phase 3, NIELIT Gorakhpur</span>
            </p>
            <p className="text-xs font-mono text-[var(--text-secondary)] flex items-center justify-center sm:justify-start gap-2">
              <span>✉️</span>
              <a
                href="mailto:kartikeyvishwakarma28@gmail.com"
                className="hover:text-[var(--accent)] underline transition-colors"
              >
                kartikeyvishwakarma28@gmail.com
              </a>
            </p>
          </div>
        </div>

        {/* PROJECT INFO CARDS (2 col grid BugCrowd style) */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Card 1 — About VibeSec */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
            <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
              <span className="text-xl">🛡️</span>
              <h2>About VibeSec</h2>
            </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              VibeSec is an AI-powered static application security testing (SAST) platform engineered
              specifically for verifying AI-generated code. AI code generators (GitHub Copilot, Cursor, ChatGPT)
              frequently produce vulnerable logic, hallucinated package dependencies, and hardcoded secrets.
              VibeSec combines deterministic AST rules with local LLM reasoning to catch these threats before deployment.
            </p>
          </div>

          {/* Card 2 — Tech Stack */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
            <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
              <span className="text-xl">⚙️</span>
              <h2>Tech Stack</h2>
            </div>
            <div className="space-y-1.5 text-xs font-mono text-[var(--text-secondary)]">
              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span>Backend Framework</span>
                <span className="text-[var(--text-primary)] font-bold">FastAPI (Python 3.10)</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span>Frontend Client</span>
                <span className="text-[var(--text-primary)] font-bold">Next.js + Tailwind CSS</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span>Local AI Inference</span>
                <span className="text-[var(--success)] font-bold">Ollama (qwen2.5-coder:7b)</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span>SAST Engine</span>
                <span className="text-[var(--text-primary)] font-bold">Semgrep & Bandit rules</span>
              </div>
            </div>
          </div>

          {/* Card 3 — Features Built */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
            <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
              <span className="text-xl">✨</span>
              <h2>Features Built</h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-[var(--text-secondary)]">
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>4 scan input modes</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>Local LLM — 0 API costs</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>Supply chain detector</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>OWASP Top 10 matrix</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>CVE NVD cross-linking</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>AI Security Chatbot</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>Real-time scan progress</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[var(--success)]">✓</span>
                <span>PDF report export</span>
              </div>
            </div>
          </div>

          {/* Card 4 — Research Basis */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
            <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
              <span className="text-xl">🔬</span>
              <h2>Research Basis</h2>
            </div>
            <div className="space-y-2 text-xs text-[var(--text-secondary)]">
              <p>
                <strong className="text-[var(--text-primary)]">Stanford 2023 Study:</strong> Developers using AI assistants write
                significantly less secure code and are more confident in its security than non-AI users.
              </p>
              <p>
                <strong className="text-[var(--text-primary)]">Slopsquatting & Hallucinations:</strong> Up to 20% of package recommendations
                by generative code models are fictitious, allowing malicious actors to squat package names.
              </p>
            </div>
          </div>
        </div>

        {/* CONTACT LINKS ROW */}
        <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm flex flex-wrap items-center justify-center gap-4">
          <a
            href="mailto:kartikeyvishwakarma28@gmail.com"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xs transition-all cursor-pointer"
          >
            <span>✉️</span>
            <span>Send Email</span>
          </a>

          <a
            href="https://github.com/KeyToCoding"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--text-primary)] text-xs font-medium border border-[var(--card-border)] hover:border-[var(--accent)] transition-all cursor-pointer"
          >
            <span>🐙</span>
            <span>GitHub Profile</span>
          </a>

          <a
            href="https://linkedin.com/in/kartikey28"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--text-primary)] text-xs font-medium border border-[var(--card-border)] hover:border-[var(--accent)] transition-all cursor-pointer"
          >
            <span>💼</span>
            <span>LinkedIn</span>
          </a>
        </div>
      </div>

      <CookieBanner />
    </div>
  );
}
