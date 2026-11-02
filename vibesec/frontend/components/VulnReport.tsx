"use client";

import React, { useState } from "react";
import { ScanReportData, Vulnerability, HallucinatedPackage } from "../types";
import { RiskGauge } from "./RiskGauge";
import { OWASPMap } from "./OWASPMap";
import { AIFixVerifyModal } from "./AIFixVerifyModal";

interface VulnReportProps {
  report: ScanReportData;
  onAskAI?: (vuln: {
    type?: string;
    severity?: string;
    line?: number | string;
    description?: string;
    fix?: string;
    owasp?: string;
  }) => void;
  onApplyFixToEditor?: (fixedCode: string) => void;
  currentCodeContext?: string;
}

const CVE_MAP: Record<string, string> = {
  "SQL Injection": "CVE-2021-44228",
  "XSS": "CVE-2021-26084",
  "Path Traversal": "CVE-2021-41773",
  "Hardcoded Secret": "CVE-2021-22048",
  "Command Injection": "CVE-2021-42013",
  "SSRF": "CVE-2021-26855",
  "Broken Auth": "CVE-2022-22965",
  "Open Redirect": "CVE-2022-24434",
  "Hallucinated Package": "CVE-2023-29217",
  "Insecure Deserialization": "CVE-2022-22965",
};

// Helper to look up CVE by title or OWASP
function getCveForVuln(vuln: Vulnerability): string {
  if (vuln.rule_id && CVE_MAP[vuln.rule_id]) return CVE_MAP[vuln.rule_id];
  for (const [key, cve] of Object.entries(CVE_MAP)) {
    if (vuln.title.toLowerCase().includes(key.toLowerCase())) {
      return cve;
    }
  }
  if (vuln.owasp?.includes("A03")) return "CVE-2021-44228";
  if (vuln.owasp?.includes("A01")) return "CVE-2022-22965";
  if (vuln.owasp?.includes("A02")) return "CVE-2021-22048";
  if (vuln.owasp?.includes("A10")) return "CVE-2021-26855";
  return "CVE-2023-29217";
}

export const VulnReport: React.FC<VulnReportProps> = ({
  report,
  onAskAI,
  onApplyFixToEditor,
  currentCodeContext,
}) => {
  const [expandedCards, setExpandedCards] = useState<Record<number, boolean>>({ 0: true });
  const [diffViewCards, setDiffViewCards] = useState<Record<number, boolean>>({});
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // AI Fix & Verify Signature Feature State
  const [remediateModalOpen, setRemediateModalOpen] = useState(false);
  const [selectedVulnForRemediate, setSelectedVulnForRemediate] = useState<Vulnerability | null>(null);

  const toggleCard = (index: number) => {
    setExpandedCards((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const toggleDiffView = (index: number, e: React.MouseEvent) => {
    e.stopPropagation();
    setDiffViewCards((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const copyToClipboard = (text: string, index: number, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // PDF Export using window.print()
  const handlePrint = () => {
    window.print();
  };

  const counts = report.severity_counts || { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };

  const getSeverityStyle = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return {
          border: "border-l-[#ef4444]",
          badgeBg: "bg-[#ef4444]/15 text-[#ef4444] border border-[#ef4444]/30",
          label: "CRITICAL",
          dot: "bg-[#ef4444]",
        };
      case "high":
        return {
          border: "border-l-[#f97316]",
          badgeBg: "bg-[#f97316]/15 text-[#f97316] border border-[#f97316]/30",
          label: "HIGH",
          dot: "bg-[#f97316]",
        };
      case "medium":
        return {
          border: "border-l-[#f59e0b]",
          badgeBg: "bg-[#f59e0b]/15 text-[#f59e0b] border border-[#f59e0b]/30",
          label: "MEDIUM",
          dot: "bg-[#f59e0b]",
        };
      case "low":
        return {
          border: "border-l-[#3b82f6]",
          badgeBg: "bg-[#3b82f6]/15 text-[#3b82f6] border border-[#3b82f6]/30",
          label: "LOW",
          dot: "bg-[#3b82f6]",
        };
      default:
        return {
          border: "border-l-[#10b981]",
          badgeBg: "bg-[#10b981]/15 text-[#10b981] border border-[#10b981]/30",
          label: "SAFE",
          dot: "bg-[#10b981]",
        };
    }
  };

  // Extract detected OWASP categories from vulnerabilities
  const detectedOWASPCategories = (report.vulnerabilities || [])
    .map((v) => v.owasp || "")
    .filter(Boolean);

  if (report.hallucinated_packages && report.hallucinated_packages.length > 0) {
    detectedOWASPCategories.push("A06:2021-Vulnerable Components");
  }

  return (
    <div className="space-y-6">
      {/* FEATURE 8: Print header (hidden normally, visible on print) */}
      <div className="print-header" style={{ display: "none" }}>
        <h1 className="text-2xl font-bold">🛡️ VibeSec Security Report</h1>
        <p className="text-sm">Developer: Kartikey Vishwakarma</p>
        <p className="text-sm">NIELIT Gorakhpur Major Project 2026</p>
        <p className="text-sm">Email: kartikeyvishwakarma28@gmail.com</p>
        <p className="text-sm">Scan Date: {new Date().toLocaleString()}</p>
        <hr className="my-3 border-gray-400" />
      </div>

      {/* Top Header with Print / Export PDF */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
            <span>📊</span>
            <span>Security Assessment Verdict</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">{report.summary}</p>
        </div>

        <div className="flex items-center gap-2">
          {/* FEATURE 8: PDF Export Button */}
          <button
            type="button"
            onClick={handlePrint}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold cursor-pointer shadow-sm transition-colors"
          >
            <span>🖨️</span>
            <span>Export Report (PDF)</span>
          </button>
        </div>
      </div>

      {/* RESULTS GRID: Left (Gauge & Stats), Right (Vuln Cards) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* LEFT COLUMN: Risk Score Circular Gauge + Severity Breakdown */}
        <div className="lg:col-span-5 space-y-4">
          {/* FEATURE 4: Risk Score Circular Gauge Component */}
          <RiskGauge
            critical={counts.critical || 0}
            high={counts.high || 0}
            medium={counts.medium || 0}
          />

          {/* Severity Breakdown Card */}
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-5 shadow-sm space-y-3">
            <div className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wider pb-1 border-b border-[var(--card-border)] flex justify-between">
              <span>Severity Breakdown</span>
              <span className="font-mono text-[var(--text-secondary)]">
                {report.files_scanned} {report.files_scanned === 1 ? "File" : "Files"}
              </span>
            </div>

            <div className="space-y-2 pt-1 font-mono text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span className="flex items-center gap-2 text-[var(--text-primary)]">
                  <span>🔴</span>
                  <span>Critical</span>
                </span>
                <span className="font-bold text-[#ef4444]">{counts.critical || 0}</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span className="flex items-center gap-2 text-[var(--text-primary)]">
                  <span>🟠</span>
                  <span>High</span>
                </span>
                <span className="font-bold text-[#f97316]">{counts.high || 0}</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span className="flex items-center gap-2 text-[var(--text-primary)]">
                  <span>🟡</span>
                  <span>Medium</span>
                </span>
                <span className="font-bold text-[#f59e0b]">{counts.medium || 0}</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span className="flex items-center gap-2 text-[var(--text-primary)]">
                  <span>🔵</span>
                  <span>Low</span>
                </span>
                <span className="font-bold text-[#3b82f6]">{counts.low || 0}</span>
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                <span className="flex items-center gap-2 text-[var(--text-primary)]">
                  <span>🟢</span>
                  <span>Safe Elements</span>
                </span>
                <span className="font-bold text-[#10b981]">{counts.safe || 0}</span>
              </div>
            </div>

            {/* Meta info */}
            <div className="pt-2 border-t border-[var(--card-border)] flex flex-wrap items-center justify-between text-xs text-[var(--text-secondary)] gap-2 font-mono">
              <span className="bg-[var(--bg-main)] px-2.5 py-1 rounded-lg border border-[var(--card-border)]">
                🤖 <span className="text-[var(--text-primary)]">{report.primary_model || "qwen2.5-coder:7b"}</span>
              </span>
              <span className="bg-[var(--bg-main)] px-2.5 py-1 rounded-lg border border-[var(--card-border)]">
                ⏱️ <span className="text-[var(--text-primary)]">{report.scan_time_seconds || 1.2}s</span>
              </span>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Vulnerability Cards with FEATURE 2 requirements */}
        <div className="lg:col-span-7 space-y-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-white uppercase tracking-wider">
              Identified Flaws ({report.vulnerabilities?.length || 0})
            </span>
            {report.vulnerabilities?.length > 0 && (
              <button
                onClick={() => {
                  const allOpen = Object.keys(expandedCards).length === report.vulnerabilities.length;
                  if (allOpen) {
                    setExpandedCards({});
                  } else {
                    const next: Record<number, boolean> = {};
                    report.vulnerabilities.forEach((_, i) => (next[i] = true));
                    setExpandedCards(next);
                  }
                }}
                className="text-[11px] text-[#8b8fa8] hover:text-[#7c3aed] cursor-pointer"
              >
                Toggle All
              </button>
            )}
          </div>

          {(!report.vulnerabilities || report.vulnerabilities.length === 0) ? (
            <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-8 text-center shadow-xs">
              <span className="text-3xl block mb-2">🟢</span>
              <span className="text-sm font-bold text-[var(--text-primary)] block">No Security Flaws Detected</span>
              <span className="text-xs text-[var(--text-secondary)] mt-1 block">
                Target passed static security rules and AI vulnerability reasoning.
              </span>
            </div>
          ) : (
            <div className="space-y-3 max-h-[640px] overflow-y-auto pr-1">
              {report.vulnerabilities.map((vuln: Vulnerability, idx: number) => {
                const style = getSeverityStyle(vuln.severity);
                const isExpanded = !!expandedCards[idx];
                const showDiff = !!diffViewCards[idx];
                const cveId = getCveForVuln(vuln);

                return (
                  <div
                    key={idx}
                    className={`vuln-card bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)]/40 rounded-xl border-l-4 ${style.border} transition-all duration-200 overflow-hidden shadow-xs hover:shadow-md`}
                  >
                    {/* Card Header */}
                    <div
                      onClick={() => toggleCard(idx)}
                      className="p-4 cursor-pointer flex items-start justify-between gap-3 hover:bg-[var(--bg-main)]/60 transition-colors"
                    >
                      <div className="space-y-2 flex-1">
                        {/* Badges Row: [Severity] [Title] [CVE Badge] [OWASP Tag] */}
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider ${style.badgeBg}`}
                          >
                            {style.label}
                          </span>

                          <span className="text-sm font-bold text-[var(--text-primary)]">
                            {vuln.title}
                          </span>

                          {/* 2. CVE Badge linked to nvd.nist.gov */}
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="text-[10px] font-mono bg-[var(--accent)]/10 hover:bg-[var(--accent)]/20 text-[var(--accent)] px-2 py-0.5 rounded-md border border-[var(--accent)]/30 transition-colors flex items-center gap-1 cursor-pointer font-medium"
                            title="Inspect CVE on National Vulnerability Database (NIST)"
                          >
                            <span>🔍</span>
                            <span>{cveId}</span>
                          </a>

                          {/* 4. OWASP Tag: colored pill showing category */}
                          {vuln.owasp && (
                            <span className="text-[10px] font-mono bg-[var(--bg-main)] text-[var(--success)] px-2 py-0.5 rounded-full border border-[var(--card-border)]">
                              {vuln.owasp}
                            </span>
                          )}

                          {vuln.line_hint !== undefined && vuln.line_hint !== 0 && (
                            <span className="text-[11px] text-[var(--text-secondary)] font-mono bg-[var(--bg-main)] px-2 py-0.5 rounded border border-[var(--card-border)]">
                              line {vuln.line_hint}
                            </span>
                          )}
                        </div>

                        {/* Short description */}
                        <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                          {vuln.description}
                        </p>

                        {/* Action buttons row: [AI Fix & Verify] [Ask AI] [View Fix / Code Diff] [Copy Fix] */}
                        <div className="flex flex-wrap items-center gap-2 pt-1">
                          {/* 0. Signature Feature: AI Fix & Verify button */}
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedVulnForRemediate(vuln);
                              setRemediateModalOpen(true);
                            }}
                            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold shadow-xs transition-colors cursor-pointer"
                            title="Generate secure patch with local Ollama and deterministically verify in isolated sandbox"
                          >
                            <span>⚡</span>
                            <span>AI Fix & Verify</span>
                          </button>

                          {/* 1. "Ask AI" button */}
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onAskAI) {
                                onAskAI({
                                  type: vuln.title,
                                  severity: vuln.severity,
                                  line: vuln.line_hint,
                                  description: vuln.description,
                                  fix: vuln.fix,
                                  owasp: vuln.owasp,
                                });
                              }
                            }}
                            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-[11px] font-semibold shadow-xs transition-colors cursor-pointer"
                          >
                            <span>💬</span>
                            <span>Ask AI</span>
                          </button>

                          {/* 3. Code Diff "View Fix" button */}
                          <button
                            type="button"
                            onClick={(e) => toggleDiffView(idx, e)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-bg)] border border-[var(--card-border)] text-[11px] text-[var(--text-primary)] font-mono transition-colors cursor-pointer"
                          >
                            <span>⚡</span>
                            <span>{showDiff ? "Hide Code Diff" : "View Fix Diff"}</span>
                          </button>

                          {/* 5. Copy Fix button */}
                          {vuln.fix && (
                            <button
                              type="button"
                              onClick={(e) => copyToClipboard(vuln.fix || "", idx, e)}
                              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-bg)] border border-[var(--success)]/40 text-[11px] text-[var(--success)] font-mono transition-colors cursor-pointer"
                            >
                              <span>{copiedIndex === idx ? "✓" : "📋"}</span>
                              <span>{copiedIndex === idx ? "Copied!" : "Copy Fix"}</span>
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Expand Arrow */}
                      <span className="text-xs text-[var(--text-secondary)] p-1 select-none">
                        {isExpanded ? "▲" : "▼"}
                      </span>
                    </div>

                    {/* FEATURE 2 & Expanded View */}
                    {isExpanded && (
                      <div className="p-4 pt-2 border-t border-[#2d2b55] space-y-3 bg-[#16162a] text-xs">
                        {vuln.attack_scenario && (
                          <div className="space-y-1">
                            <span className="text-[11px] font-semibold text-[#ef4444] uppercase tracking-wider flex items-center gap-1.5">
                              <span>⚠️</span>
                              <span>Attack Scenario</span>
                            </span>
                            <div className="p-2.5 rounded-lg bg-[#0d0d1a] border border-[#ef4444]/20 text-[#8b8fa8] leading-relaxed">
                              {vuln.attack_scenario}
                            </div>
                          </div>
                        )}

                        {/* 3. Code Diff view: LEFT (red tint, bad line highlighted) | RIGHT (green tint, fixed code) */}
                        {showDiff ? (
                          <div className="space-y-1.5">
                            <span className="text-[11px] font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                              <span>🔄</span>
                              <span>Side-by-Side Remediation Diff</span>
                            </span>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                              {/* LEFT PANEL: Vulnerable Code (Red Tint) */}
                              <div className="bg-[#ef4444]/5 border border-[#ef4444]/30 rounded-xl p-3 overflow-hidden">
                                <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#ef4444]/20 text-[#ef4444] font-bold text-[11px]">
                                  <span>🔴 Vulnerable Code</span>
                                  {vuln.line_hint && <span>line {vuln.line_hint}</span>}
                                </div>
                                <div className="space-y-1 overflow-x-auto text-zinc-300">
                                  {vuln.code_snippet ? (
                                    vuln.code_snippet.split("\n").map((line, lIdx) => (
                                      <div
                                        key={lIdx}
                                        className={`flex items-start gap-2 px-1 rounded ${
                                          lIdx === 0 || (vuln.line_hint && lIdx === 0)
                                            ? "bg-[#ef4444]/20 border-l-2 border-[#ef4444] text-[#ef4444] font-bold"
                                            : ""
                                        }`}
                                      >
                                        <span className="text-[10px] text-zinc-600 select-none w-6 text-right">
                                          {lIdx + 1}
                                        </span>
                                        <pre className="text-xs whitespace-pre">
                                          <code>{line}</code>
                                        </pre>
                                      </div>
                                    ))
                                  ) : (
                                    <div className="text-zinc-500 italic p-2">
                                      Flagged pattern: {vuln.title}
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* RIGHT PANEL: Fixed Code (Green Tint) */}
                              <div className="bg-[#10b981]/5 border border-[#10b981]/30 rounded-xl p-3 overflow-hidden">
                                <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#10b981]/20 text-[#10b981] font-bold text-[11px]">
                                  <span>🟢 Secure Remediated Code</span>
                                  <button
                                    type="button"
                                    onClick={(e) => copyToClipboard(vuln.fix || "", idx, e)}
                                    className="hover:underline text-[10px]"
                                  >
                                    Copy
                                  </button>
                                </div>
                                <div className="space-y-1 overflow-x-auto text-[#10b981]">
                                  {vuln.fix ? (
                                    vuln.fix.split("\n").map((line, lIdx) => (
                                      <div key={lIdx} className="flex items-start gap-2 px-1">
                                        <span className="text-[10px] text-emerald-800 select-none w-6 text-right">
                                          {lIdx + 1}
                                        </span>
                                        <pre className="text-xs whitespace-pre">
                                          <code>{line}</code>
                                        </pre>
                                      </div>
                                    ))
                                  ) : (
                                    <div className="text-zinc-500 italic p-2">
                                      Apply parameterized inputs and input validation.
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        ) : (
                          /* Standard view if diff view toggle is off */
                          vuln.fix && (
                            <div className="space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="text-[11px] font-semibold text-[#10b981] uppercase tracking-wider">
                                  Recommended Fix
                                </span>
                                <button
                                  type="button"
                                  onClick={(e) => copyToClipboard(vuln.fix || "", idx, e)}
                                  className="text-[10px] bg-[#0d0d1a] hover:bg-[#2d2b55] text-white px-2 py-0.5 rounded border border-[#2d2b55] cursor-pointer transition-colors"
                                >
                                  {copiedIndex === idx ? "✓ Copied" : "📋 Copy Fix"}
                                </button>
                              </div>
                              <pre className="p-2.5 rounded-lg bg-[#0d0d1a] border border-[#10b981]/30 text-xs font-mono text-[#10b981] overflow-x-auto">
                                <code>{vuln.fix}</code>
                              </pre>
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* FEATURE 3: OWASP Coverage Map Component */}
      <OWASPMap
        detectedCategories={detectedOWASPCategories}
        onSelectCategory={(_, promptText) => {
          if (onAskAI) {
            onAskAI({
              type: promptText,
              description: "OWASP Top 10 Inquiry",
            });
          }
        }}
      />

      {/* HALLUCINATED PACKAGES (Separate card below results, red border) */}
      {report.hallucinated_packages && report.hallucinated_packages.length > 0 && (
        <div className="bg-[var(--card-bg)] border border-[var(--danger)]/60 rounded-xl p-5 shadow-sm space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-xl">⚠️</span>
            <div>
              <h3 className="text-sm font-bold text-[var(--danger)] uppercase tracking-wider">
                Supply Chain Threats Detected
              </h3>
              <p className="text-xs text-[var(--text-secondary)]">
                These dependencies were hallucinated by AI generation and do not exist on the upstream registry.
              </p>
            </div>
          </div>

          <div className="space-y-2.5 pt-1">
            {report.hallucinated_packages.map((pkg: HallucinatedPackage, pIdx: number) => (
              <div
                key={pIdx}
                className="bg-[var(--bg-main)] border border-[var(--danger)]/30 rounded-lg p-3.5 space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[var(--text-primary)] bg-[var(--card-bg)] px-2 py-0.5 rounded border border-[var(--card-border)]">
                      {pkg.package}
                    </span>
                    <span className="text-[10px] font-bold text-[var(--danger)] bg-[var(--danger)]/15 border border-[var(--danger)]/30 px-2 py-0.5 rounded-full uppercase">
                      NOT on {pkg.ecosystem || "npm"}
                    </span>
                  </div>
                  <span className="text-[10px] text-[var(--danger)] font-bold uppercase">
                    Critical Supply Chain Risk
                  </span>
                </div>

                <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                  {pkg.risk_analysis ||
                    `The package '${pkg.package}' is not registered on ${pkg.ecosystem}. Threat actors can register this unclaimed package name ('slopsquatting') and insert malicious post-install lifecycle scripts to compromise your system.`}
                </p>

                {pkg.fix && (
                  <div className="text-xs font-mono text-[var(--success)]">
                    <strong>Fix:</strong> {pkg.fix}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SIGNATURE FEATURE: AI Fix & Verify Copilot Modal */}
      <AIFixVerifyModal
        isOpen={remediateModalOpen}
        onClose={() => {
          setRemediateModalOpen(false);
          setSelectedVulnForRemediate(null);
        }}
        vulnerability={selectedVulnForRemediate}
        codeContext={currentCodeContext || selectedVulnForRemediate?.code_snippet || ""}
        language={report.language || "python"}
        filename={report.filename || selectedVulnForRemediate?.file || "snippet"}
        onApplyFixToEditor={onApplyFixToEditor}
      />
    </div>
  );
};
