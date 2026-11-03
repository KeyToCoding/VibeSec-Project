/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { Sidebar, NavTab } from "./components/Sidebar";
import { ScanInput, InputMode } from "./components/ScanInput";
import { VulnReport } from "./components/VulnReport";
import { SecurityBot, VulnContext } from "./components/SecurityBot";
import { TrendChart } from "./components/TrendChart";
import { ThemeToggle } from "./components/ThemeToggle";
import { CookieBanner } from "./components/CookieBanner";
import { ScanReportData } from "./types";
import { getApiUrl, getApiHeaders, ensureAuthenticatedSession } from "./config";

interface StoredScan {
  id: number | string;
  date: string;
  type: string;
  files: number;
  critical: number;
  high: number;
  medium: number;
  riskScore: number;
  vulnerabilities: any[];
  summary?: string;
  primary_model?: string;
  scan_time_seconds?: number;
  hallucinated_packages?: any[];
  severity_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
}

export default function App() {
  const [activeNav, setActiveNav] = useState<NavTab>("dashboard");
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [report, setReport] = useState<ScanReportData | null>(null);
  const [lastScannedCode, setLastScannedCode] = useState<string>("");

  // SecurityBot state
  const [botOpen, setBotOpen] = useState(false);
  const [botVulnContext, setBotVulnContext] = useState<VulnContext | null>(null);
  const [botInitialPrompt, setBotInitialPrompt] = useState<string | null>(null);

  // Stats from localStorage
  const [stats, setStats] = useState({
    totalScans: 0,
    criticalFound: 0,
    filesScanned: 0,
    safeFiles: 0,
  });

  const [historyList, setHistoryList] = useState<StoredScan[]>([]);
  const [historyFilter, setHistoryFilter] = useState("");
  const [historySortBy, setHistorySortBy] = useState<"date" | "riskScore" | "critical">("date");
  const [selectedScanIds, setSelectedScanIds] = useState<Record<string | number, boolean>>({});

  // Load history & aggregate stats
  const loadHistoryAndStats = () => {
    try {
      let stored = localStorage.getItem("vibesec_scans");
      if (!stored) {
        stored = localStorage.getItem("vibesec_history");
      }
      if (stored) {
        const parsed: any[] = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          const normalized: StoredScan[] = parsed.map((item: any, i: number) => ({
            id: item.id || item.scan_id || `scan-${i}`,
            date: item.date || item.created_at || new Date().toISOString(),
            type: item.type || item.input_type || "code",
            files: item.files || item.files_scanned || 1,
            critical: item.critical !== undefined ? item.critical : item.severity_counts?.critical || 0,
            high: item.high !== undefined ? item.high : item.severity_counts?.high || 0,
            medium: item.medium !== undefined ? item.medium : item.severity_counts?.medium || 0,
            riskScore:
              item.riskScore !== undefined
                ? item.riskScore
                : (item.critical || item.severity_counts?.critical || 0) * 10 +
                  (item.high || item.severity_counts?.high || 0) * 5 +
                  (item.medium || item.severity_counts?.medium || 0) * 2,
            vulnerabilities: item.vulnerabilities || [],
            summary: item.summary || "Security audit snapshot",
            primary_model: item.primary_model || "qwen2.5-coder:7b",
            scan_time_seconds: item.scan_time_seconds || 1.2,
            hallucinated_packages: item.hallucinated_packages || [],
            severity_counts: item.severity_counts || {
              critical: item.critical || 0,
              high: item.high || 0,
              medium: item.medium || 0,
              low: 0,
              safe: (item.vulnerabilities || []).length === 0 ? 1 : 0,
            },
          }));

          setHistoryList(normalized);
          let crit = 0;
          let files = 0;
          let safe = 0;

          normalized.forEach((scan) => {
            crit += scan.critical;
            files += scan.files;
            safe += scan.severity_counts?.safe || (scan.vulnerabilities.length === 0 ? 1 : 0);
          });

          setStats({
            totalScans: normalized.length,
            criticalFound: crit,
            filesScanned: files,
            safeFiles: safe,
          });
        }
      }
    } catch (e) {
      console.error("Error loading localStorage stats", e);
    }
  };

  const syncServerHistory = async () => {
    try {
      const res = await fetch(getApiUrl("/api/history"), {
        headers: getApiHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          const stored = localStorage.getItem("vibesec_scans") || "[]";
          const existing = JSON.parse(stored);
          const existingIds = new Set(existing.map((s: any) => String(s.id || s.scan_id)));
          const newItems = data
            .filter((s: any) => s.scan_id && !existingIds.has(String(s.scan_id)))
            .map((s: any) => ({
              id: s.scan_id,
              date: s.created_at || new Date().toISOString(),
              type: s.input_type || "code",
              files: s.files_scanned || 1,
              critical: s.severity_counts?.critical || 0,
              high: s.severity_counts?.high || 0,
              medium: s.severity_counts?.medium || 0,
              riskScore: (s.severity_counts?.critical || 0) * 10 + (s.severity_counts?.high || 0) * 5 + (s.severity_counts?.medium || 0) * 2,
              vulnerabilities: s.vulnerabilities || [],
              summary: s.summary || "Scan report",
              primary_model: s.primary_model || "qwen2.5-coder:7b",
              scan_time_seconds: s.scan_time_seconds || 1.0,
              hallucinated_packages: s.hallucinated_packages || [],
              severity_counts: s.severity_counts,
            }));

          if (newItems.length > 0) {
            const combined = [...newItems, ...existing].slice(0, 50);
            localStorage.setItem("vibesec_scans", JSON.stringify(combined));
            localStorage.setItem("vibesec_history", JSON.stringify(combined));
            loadHistoryAndStats();
          }
        }
      }
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    ensureAuthenticatedSession().then(() => {
      syncServerHistory();
    });
    loadHistoryAndStats();
  }, []);

  // Save scan to localStorage key "vibesec_scans"
  const saveScan = (result: ScanReportData, scanType: string) => {
    try {
      const scans = JSON.parse(localStorage.getItem("vibesec_scans") || "[]");
      const crit = result.severity_counts?.critical || 0;
      const high = result.severity_counts?.high || 0;
      const med = result.severity_counts?.medium || 0;

      const newScan: StoredScan = {
        id: Date.now(),
        date: new Date().toISOString(),
        type: scanType,
        files: result.files_scanned || 1,
        critical: crit,
        high: high,
        medium: med,
        riskScore: crit * 10 + high * 5 + med * 2,
        vulnerabilities: result.vulnerabilities || [],
        summary: result.summary,
        primary_model: result.primary_model,
        scan_time_seconds: result.scan_time_seconds,
        hallucinated_packages: result.hallucinated_packages,
        severity_counts: result.severity_counts,
      };

      scans.unshift(newScan);
      const trimmed = scans.slice(0, 50);
      localStorage.setItem("vibesec_scans", JSON.stringify(trimmed));
      localStorage.setItem("vibesec_history", JSON.stringify(trimmed));
      loadHistoryAndStats();
    } catch (err) {
      console.warn("Could not save to localStorage", err);
    }
  };

  const handleScan = async (type: InputMode, payload: any) => {
    setIsScanning(true);
    setReport(null);
    if (type === "code" && payload.code) {
      setLastScannedCode(payload.code);
    } else if (payload.content) {
      setLastScannedCode(payload.content);
    }

    try {
      let response: Response;
      if (type === "upload") {
        if (payload.file && payload.file.size > 100 * 1024 * 1024) {
          throw new Error(
            `Selected file exceeds the 100MB limit (${(payload.file.size / (1024 * 1024)).toFixed(1)}MB). Please choose a file under 100MB.`
          );
        }
        const formData = new FormData();
        formData.append("file", payload.file);
        response = await fetch(getApiUrl("/api/scan/upload"), {
          method: "POST",
          headers: getApiHeaders(),
          body: formData,
        });
      } else {
        response = await fetch(getApiUrl(`/api/scan/${type}`), {
          method: "POST",
          headers: getApiHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload),
        });
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        const message =
          errData.error ||
          errData.detail ||
          (response.status === 413
            ? "Uploaded file exceeds the maximum allowed limit of 100MB."
            : `Scan failed with status ${response.status}`);
        throw new Error(message);
      }

      const scanResult: ScanReportData = await response.json();
      setReport(scanResult);

      // Save to localStorage
      saveScan(scanResult, type);

      // MODE A: Auto-open bot when vulnerability detected
      if (scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0) {
        const topVuln = scanResult.vulnerabilities[0];
        setBotVulnContext({
          type: topVuln.title,
          severity: topVuln.severity,
          line: topVuln.line_hint,
          description: topVuln.description,
          fix: topVuln.fix,
          owasp: topVuln.owasp,
        });
        setBotOpen(true);
      }

      // Smooth scroll to results
      setTimeout(() => {
        const resultsEl = document.getElementById("results-section");
        if (resultsEl) {
          resultsEl.scrollIntoView({ behavior: "smooth" });
        }
      }, 150);
    } catch (err: any) {
      alert(`Audit Failure: ${err?.message || "Could not complete scan"}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleAskAI = (vuln: VulnContext) => {
    setBotVulnContext(vuln);
    setBotOpen(true);
  };

  const handleClearHistory = () => {
    if (confirm("Clear local scan history?")) {
      localStorage.removeItem("vibesec_scans");
      localStorage.removeItem("vibesec_history");
      setHistoryList([]);
      setSelectedScanIds({});
      setStats({ totalScans: 0, criticalFound: 0, filesScanned: 0, safeFiles: 0 });
    }
  };

  const handleExportSelected = () => {
    const selectedList = historyList.filter((s) => selectedScanIds[s.id]);
    const itemsToExport = selectedList.length > 0 ? selectedList : historyList;

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(itemsToExport, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vibesec_history_export_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredHistory = historyList.filter((scan) => {
    if (!historyFilter.trim()) return true;
    const query = historyFilter.toLowerCase();
    return (
      scan.type.toLowerCase().includes(query) ||
      scan.date.toLowerCase().includes(query) ||
      (scan.vulnerabilities || []).some(
        (v: any) =>
          (v.title && v.title.toLowerCase().includes(query)) ||
          (v.owasp && v.owasp.toLowerCase().includes(query))
      )
    );
  });

  const sortedHistory = [...filteredHistory].sort((a, b) => {
    if (historySortBy === "riskScore") return (b.riskScore || 0) - (a.riskScore || 0);
    if (historySortBy === "critical") return (b.critical || 0) - (a.critical || 0);
    return new Date(b.date).getTime() - new Date(a.date).getTime();
  });

  return (
    <div className="min-h-screen bg-[var(--bg-main)] text-[var(--text-primary)] font-sans flex selection:bg-[var(--accent)]/30 selection:text-[var(--text-primary)] transition-colors">
      {/* 1. Left Sidebar Navigation */}
      <Sidebar
        activeTab={activeNav}
        onTabChange={(tab) => {
          setActiveNav(tab);
          if (tab === "scan") {
            const scanEl = document.getElementById("scan-panel");
            if (scanEl) scanEl.scrollIntoView({ behavior: "smooth" });
          } else if (tab === "chat") {
            setBotOpen(true);
          }
        }}
        mobileOpen={mobileSidebarOpen}
        onMobileClose={() => setMobileSidebarOpen(false)}
      />

      {/* 2. Main Content Area */}
      <div className="flex-1 md:pl-[220px] flex flex-col min-h-screen">
        {/* BugCrowd Enterprise Top Bar */}
        <header className="topbar h-16 bg-[var(--card-bg)]/80 backdrop-blur-md border-b border-[var(--card-border)] px-4 md:px-8 flex items-center justify-between sticky top-0 z-30 transition-colors">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileSidebarOpen(true)}
              className="md:hidden text-lg p-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              ☰
            </button>
            <div>
              <h1 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-1.5">
                <span>Welcome, Kartikey</span>
                <span>👋</span>
              </h1>
              <p className="text-[10px] text-[var(--text-secondary)] hidden sm:block">
                NIELIT Gorakhpur Major Project 2026 · ISEA Phase 3
              </p>
            </div>
          </div>

          {/* Search bar */}
          <div className="hidden sm:flex items-center flex-1 max-w-xs mx-4">
            <div className="relative w-full">
              <span className="absolute left-3 top-2.5 text-xs text-[var(--text-secondary)]">🔍</span>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scans, rules, OWASP..."
                className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              />
            </div>
          </div>

          {/* Right quick actions, ThemeToggle & avatar */}
          <div className="flex items-center gap-2.5">
            <ThemeToggle />

            <button
              onClick={() => setBotOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--accent)]/10 hover:bg-[var(--accent)]/20 text-[var(--accent)] border border-[var(--accent)]/30 text-xs font-semibold cursor-pointer transition-colors"
            >
              <span className="w-2 h-2 rounded-full bg-[var(--success)] animate-pulse"></span>
              <span>Ask AI</span>
            </button>

            <div className="flex items-center gap-2 pl-2 border-l border-[var(--card-border)]">
              <button
                onClick={() => setActiveNav("contact")}
                title="View Profile (Kartikey Vishwakarma)"
                className="relative w-8 h-8 rounded-full overflow-hidden ring-2 ring-[var(--accent)]/40 hover:ring-[var(--accent)] transition-all cursor-pointer shadow-sm flex items-center justify-center bg-gradient-to-tr from-[var(--accent)] to-amber-500 font-bold text-xs text-white"
              >
                <span className="select-none">KV</span>
                <img
                  src="/kartikey.jpg"
                  alt="Kartikey Vishwakarma"
                  className="absolute inset-0 w-full h-full object-cover"
                  onError={(e) => {
                    (e.currentTarget as HTMLElement).style.display = "none";
                  }}
                />
              </button>
            </div>
          </div>
        </header>

        {/* Dynamic Body based on Active Navigation Tab */}
        <main className="p-4 md:p-8 space-y-6 flex-1">
          {/* TAB 1: HISTORY VIEW */}
          {activeNav === "history" && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[var(--card-border)]">
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setActiveNav("dashboard")}
                    className="px-3 py-1.5 rounded-lg bg-[var(--card-bg)] hover:bg-[var(--bg-main)] text-xs font-medium text-[var(--text-primary)] border border-[var(--card-border)] transition-colors cursor-pointer"
                  >
                    ← Back to Dashboard
                  </button>
                  <div>
                    <h2 className="text-xl font-bold flex items-center gap-2 text-[var(--text-primary)]">
                      <span>📋</span>
                      <span>Scan History Ledger</span>
                    </h2>
                    <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                      Audit history stored securely in your browser session (localStorage)
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  {historyList.length > 0 && (
                    <button
                      onClick={handleExportSelected}
                      className="px-3.5 py-1.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold transition-colors cursor-pointer shadow-sm"
                    >
                      📥 Export JSON
                    </button>
                  )}
                  {historyList.length > 0 && (
                    <button
                      onClick={handleClearHistory}
                      className="px-3 py-1.5 rounded-lg bg-[var(--danger)]/15 hover:bg-[var(--danger)]/25 text-[var(--danger)] border border-[var(--danger)]/30 text-xs font-medium transition-colors cursor-pointer"
                    >
                      Clear History
                    </button>
                  )}
                </div>
              </div>

              {historyList.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-3 bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-3 shadow-xs">
                  <div className="flex-1 min-w-[240px] relative">
                    <span className="absolute left-3 top-2.5 text-xs text-[var(--text-secondary)]">🔍</span>
                    <input
                      type="text"
                      value={historyFilter}
                      onChange={(e) => setHistoryFilter(e.target.value)}
                      placeholder="Search scan type, vulnerability, OWASP..."
                      className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)]"
                    />
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-[var(--text-secondary)]">Sort By:</span>
                    <select
                      value={historySortBy}
                      onChange={(e: any) => setHistorySortBy(e.target.value)}
                      className="bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] cursor-pointer"
                    >
                      <option value="date">Date (Newest First)</option>
                      <option value="riskScore">Risk Score (Highest First)</option>
                      <option value="critical">Critical Count (Highest First)</option>
                    </select>
                  </div>
                </div>
              )}

              {/* Table */}
              <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl overflow-hidden shadow-sm">
                {historyList.length === 0 ? (
                  <div className="p-16 text-center space-y-3">
                    <div className="w-16 h-16 mx-auto rounded-full bg-[var(--bg-main)] border border-[var(--card-border)] flex items-center justify-center text-3xl shadow-inner">
                      🛡️
                    </div>
                    <h3 className="text-base font-bold text-[var(--text-primary)]">No scans yet. Run your first scan!</h3>
                    <p className="text-xs text-[var(--text-secondary)] max-w-sm mx-auto">
                      Audit Python, JavaScript, URLs, or repositories using VibeSec to track your security trajectory.
                    </p>
                    <div className="pt-2">
                      <button
                        onClick={() => setActiveNav("dashboard")}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
                      >
                        <span>🚀</span>
                        <span>Start New Security Scan</span>
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[var(--bg-main)] text-[var(--text-secondary)] border-b border-[var(--card-border)]">
                        <tr>
                          <th className="p-3.5 w-10 text-center">
                            <input
                              type="checkbox"
                              checked={historyList.length > 0 && Object.keys(selectedScanIds).length === historyList.length}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  const all: Record<string | number, boolean> = {};
                                  historyList.forEach((s) => (all[s.id] = true));
                                  setSelectedScanIds(all);
                                } else {
                                  setSelectedScanIds({});
                                }
                              }}
                              className="rounded accent-[var(--accent)] cursor-pointer"
                            />
                          </th>
                          <th className="p-3.5">#</th>
                          <th className="p-3.5">Date & Time</th>
                          <th className="p-3.5">Scan Type</th>
                          <th className="p-3.5">Files</th>
                          <th className="p-3.5">Critical</th>
                          <th className="p-3.5">High</th>
                          <th className="p-3.5">Medium</th>
                          <th className="p-3.5">Risk Score</th>
                          <th className="p-3.5 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[var(--card-border)]">
                        {sortedHistory.map((scan, idx) => {
                          const crit = scan.critical || 0;
                          const high = scan.high || 0;
                          const med = scan.medium || 0;
                          const isClean = crit === 0 && high === 0 && med === 0;

                          let rowTint = "hover:bg-[var(--bg-main)]/60";
                          if (crit > 0) rowTint = "bg-[var(--danger)]/5 hover:bg-[var(--danger)]/10";
                          else if (high > 0) rowTint = "bg-[var(--accent)]/5 hover:bg-[var(--accent)]/10";
                          else if (isClean) rowTint = "bg-[var(--success)]/5 hover:bg-[var(--success)]/10";

                          return (
                            <tr
                              key={scan.id || idx}
                              onClick={() => {
                                setReport({
                                  scan_id: String(scan.id),
                                  created_at: scan.date,
                                  input_type: scan.type,
                                  vulnerabilities: scan.vulnerabilities,
                                  hallucinated_packages: scan.hallucinated_packages,
                                  severity_counts: scan.severity_counts || {
                                    critical: scan.critical,
                                    high: scan.high,
                                    medium: scan.medium,
                                    low: 0,
                                    safe: isClean ? 1 : 0,
                                  },
                                  files_scanned: scan.files,
                                  summary: scan.summary || `Scan report for ${scan.type}`,
                                  primary_model: scan.primary_model || "qwen2.5-coder:7b",
                                  scan_time_seconds: scan.scan_time_seconds || 1.2,
                                });
                                setActiveNav("dashboard");
                              }}
                              className={`cursor-pointer transition-colors ${rowTint}`}
                            >
                              <td className="p-3.5 text-center" onClick={(e) => e.stopPropagation()}>
                                <input
                                  type="checkbox"
                                  checked={!!selectedScanIds[scan.id]}
                                  onChange={() =>
                                    setSelectedScanIds((prev) => ({
                                      ...prev,
                                      [scan.id]: !prev[scan.id],
                                    }))
                                  }
                                  className="rounded accent-[var(--accent)] cursor-pointer"
                                />
                              </td>
                              <td className="p-3.5 text-[var(--text-secondary)] font-mono">{idx + 1}</td>
                              <td className="p-3.5 text-[var(--text-primary)] whitespace-nowrap">
                                {new Date(scan.date).toLocaleString([], {
                                  month: "short",
                                  day: "numeric",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                })}
                              </td>
                              <td className="p-3.5">
                                <span className="uppercase text-[10px] font-bold px-2 py-0.5 rounded bg-[var(--bg-main)] border border-[var(--card-border)] text-[var(--accent)]">
                                  {scan.type}
                                </span>
                              </td>
                              <td className="p-3.5 text-[var(--text-primary)] font-bold">{scan.files}</td>
                              <td className="p-3.5 font-bold text-[var(--danger)]">{crit}</td>
                              <td className="p-3.5 font-bold text-orange-500">{high}</td>
                              <td className="p-3.5 font-bold text-amber-500">{med}</td>
                              <td className="p-3.5">
                                <span
                                  className={`font-bold px-2 py-0.5 rounded text-[10px] ${
                                    scan.riskScore > 70
                                      ? "bg-[var(--danger)]/15 text-[var(--danger)] border border-[var(--danger)]/30"
                                      : scan.riskScore > 40
                                      ? "bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/30"
                                      : "bg-[var(--success)]/15 text-[var(--success)] border border-[var(--success)]/30"
                                  }`}
                                >
                                  {scan.riskScore}
                                </span>
                              </td>
                              <td className="p-3.5 text-right whitespace-nowrap text-[var(--accent)] hover:underline font-bold">
                                View Report →
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: CONTACT PAGE (FEATURE 9) */}
          {activeNav === "contact" && (
            <div className="max-w-4xl mx-auto space-y-6 animate-in fade-in duration-200">
              <div className="flex items-center justify-between pb-4 border-b border-[var(--card-border)]">
                <button
                  onClick={() => setActiveNav("dashboard")}
                  className="px-3 py-1.5 rounded-lg bg-[var(--card-bg)] hover:bg-[var(--bg-main)] text-xs font-medium text-[var(--text-primary)] border border-[var(--card-border)] transition-colors cursor-pointer"
                >
                  ← Back to Dashboard
                </button>
                <span className="text-xs font-mono text-[var(--text-secondary)]">
                  NIELIT Gorakhpur Major Project · 2026
                </span>
              </div>

              {/* HEADER SECTION */}
              <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-2xl p-6 sm:p-8 shadow-sm relative overflow-hidden flex flex-col sm:flex-row items-center sm:items-start gap-6 text-center sm:text-left transition-all">
                {/* Avatar Profile Photo */}
                <div className="relative w-28 h-28 rounded-2xl overflow-hidden shadow-lg shrink-0 ring-2 ring-[var(--accent)]/40 bg-gradient-to-tr from-[var(--accent)] to-amber-500 flex items-center justify-center font-extrabold text-3xl text-white">
                  <span className="select-none">KV</span>
                  <img
                    src="/kartikey.jpg"
                    alt="Kartikey Vishwakarma"
                    className="absolute inset-0 w-full h-full object-cover"
                    onError={(e) => {
                      (e.currentTarget as HTMLElement).style.display = "none";
                    }}
                  />
                </div>

                <div className="space-y-2 flex-1">
                  <div className="inline-block px-3 py-1 rounded-md text-[11px] font-mono font-bold bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/30 uppercase tracking-wider mb-1">
                    Security Researcher & Developer
                  </div>
                  <h2 className="text-2xl sm:text-3xl font-extrabold text-[var(--text-primary)] tracking-tight">
                    Kartikey Vishwakarma
                  </h2>
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

              {/* PROJECT INFO CARDS (2 col grid) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
                  <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
                    <span className="text-xl">🛡️</span>
                    <h3>About VibeSec</h3>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                    VibeSec is an AI-powered SAST platform for AI-generated code. Built as NIELIT Gorakhpur Major Project 2026 by Kartikey Vishwakarma.
                  </p>
                </div>

                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
                  <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
                    <span className="text-xl">⚙️</span>
                    <h3>Tech Stack</h3>
                  </div>
                  <div className="space-y-1.5 text-xs font-mono text-[var(--text-secondary)]">
                    <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                      <span>Backend</span>
                      <span className="text-[var(--text-primary)] font-bold">FastAPI • Python 3.10</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-main)] border border-[var(--card-border)]">
                      <span>Inference</span>
                      <span className="text-[var(--success)] font-bold">Ollama (qwen2.5-coder:7b)</span>
                    </div>
                  </div>
                </div>

                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
                  <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
                    <span className="text-xl">✨</span>
                    <h3>Features Built</h3>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-[var(--text-secondary)]">
                    <div>✅ 4 scan modes (Code/URL/File/GitHub)</div>
                    <div>✅ Local LLM — no API limits</div>
                    <div>✅ Supply chain attack detection</div>
                    <div>✅ OWASP Top 10 mapping</div>
                    <div>✅ CVE database integration</div>
                    <div>✅ AI Security Chatbot</div>
                    <div>✅ Real-time scan progress</div>
                    <div>✅ PDF report export</div>
                  </div>
                </div>

                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] hover:border-[var(--accent)] rounded-xl p-6 shadow-sm hover:shadow-md hover:-translate-y-0.5 space-y-3 transition-all">
                  <div className="flex items-center gap-2.5 text-base font-bold text-[var(--text-primary)]">
                    <span className="text-xl">🔬</span>
                    <h3>Research Basis</h3>
                  </div>
                  <div className="space-y-1.5 text-xs text-[var(--text-secondary)] font-mono">
                    <p>• Stanford 2023: AI code has 2.74× more vulns</p>
                    <p>• 20% AI packages are hallucinated</p>
                    <p>• First tool to detect slopsquatting attacks</p>
                  </div>
                </div>
              </div>

              {/* CONTACT LINKS ROW */}
              <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm flex flex-wrap items-center justify-center gap-4">
                <a
                  href="mailto:kartikeyvishwakarma28@gmail.com"
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xs transition-all cursor-pointer"
                >
                  <span className="text-base">📧</span>
                  <span>Email</span>
                </a>
                <a
                  href="https://github.com/KeyToCoding"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--text-primary)] text-xs font-medium border border-[var(--card-border)] hover:border-[var(--accent)] transition-all cursor-pointer"
                >
                  <span className="text-base">🐙</span>
                  <span>GitHub</span>
                </a>
                <a
                  href="https://linkedin.com/in/kartikey28"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--text-primary)] text-xs font-medium border border-[var(--card-border)] hover:border-[var(--accent)] transition-all cursor-pointer"
                >
                  <span className="text-base">💼</span>
                  <span>LinkedIn</span>
                </a>
              </div>

              {/* FOOTER NOTE */}
              <div className="text-center py-4 border-t border-[var(--card-border)]/60 text-xs text-[var(--text-secondary)] font-mono">
                Built with ❤️ for NIELIT Gorakhpur · ISEA Phase 3 Internship Project · 2026
              </div>
            </div>
          )}

          {/* TAB 3: SETTINGS PANEL */}
          {activeNav === "settings" && (
            <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm space-y-4 max-w-2xl animate-in fade-in duration-200">
              <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2 pb-3 border-b border-[var(--card-border)]">
                <span className="text-[var(--accent)]">⚙️</span>
                <span>Scanner Engine Configuration</span>
              </h2>

              <div className="space-y-4 text-xs">
                <div>
                  <label className="block text-[var(--text-secondary)] mb-1 font-medium">Primary LLM Inference (Ollama)</label>
                  <input
                    type="text"
                    defaultValue="http://localhost:11434"
                    readOnly
                    className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-3 py-2 text-[var(--text-primary)] font-mono"
                  />
                  <p className="text-[11px] text-[var(--text-secondary)] mt-1">Default model: qwen2.5-coder:7b</p>
                </div>

                <div className="p-3.5 bg-[var(--bg-main)] rounded-lg border border-[var(--card-border)] text-[var(--text-secondary)] space-y-1">
                  <strong className="text-[var(--text-primary)] block mb-1">NIELIT Gorakhpur Major Project 2026</strong>
                  <p>Author: Kartikey Vishwakarma</p>
                  <p>Email: kartikeyvishwakarma28@gmail.com</p>
                  <p>Stack: FastAPI • Next.js • Ollama • Semgrep • MongoDB</p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: DASHBOARD / NEW SCAN (Default) */}
          {(activeNav === "dashboard" || activeNav === "scan" || activeNav === "chat") && (
            <>
              {/* STATS ROW (4 cards BugCrowd style with hover lift) */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-4 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all">
                  <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] mb-1">
                    <span className="font-medium">Total Scans</span>
                    <span className="text-[10px] text-[var(--accent)] bg-[var(--accent)]/10 font-semibold px-2 py-0.5 rounded-md">
                      All-time
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-[var(--accent)]">
                    {stats.totalScans}
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-1 flex items-center gap-1">
                    <span className="text-[var(--success)] font-medium">↑ Active</span>
                    <span>in browser session</span>
                  </div>
                </div>

                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-4 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all">
                  <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] mb-1">
                    <span className="font-medium">Critical Flaws</span>
                    <span className="text-[10px] text-[var(--danger)] bg-[var(--danger)]/10 font-semibold px-2 py-0.5 rounded-md">
                      High severity
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-[var(--danger)]">
                    {stats.criticalFound}
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-1">
                    <span>Direct exploits flagged</span>
                  </div>
                </div>

                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-4 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all">
                  <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] mb-1">
                    <span className="font-medium">Files Audited</span>
                    <span className="text-[10px] text-blue-500 bg-blue-500/10 font-semibold px-2 py-0.5 rounded-md">
                      AST parsed
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-[var(--text-primary)]">
                    {stats.filesScanned}
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-1">
                    <span>Vendor directories excluded</span>
                  </div>
                </div>

                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-4 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all">
                  <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] mb-1">
                    <span className="font-medium">Packages OK</span>
                    <span className="text-[10px] text-[var(--success)] bg-[var(--success)]/10 font-semibold px-2 py-0.5 rounded-md">
                      Verified
                    </span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-[var(--success)]">
                    {stats.safeFiles}
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-1">
                    <span>Registry integrity pass</span>
                  </div>
                </div>
              </div>

              {/* FEATURE 5: Severity Trend Chart */}
              <TrendChart data={historyList} />

              {/* SCAN PANEL (Main Input Card) */}
              <div id="scan-panel">
                <ScanInput onScan={handleScan} isScanning={isScanning} />
              </div>

              {/* RESULTS PANEL (Appears after scan) */}
              {report && (
                <div id="results-section" className="pt-2">
                  <VulnReport
                    report={report}
                    onAskAI={handleAskAI}
                    currentCodeContext={lastScannedCode}
                    onApplyFixToEditor={(fixedCode) => {
                      setLastScannedCode(fixedCode);
                    }}
                  />
                </div>
              )}
            </>
          )}
        </main>
      </div>

      {/* FEATURE 1: Contextual Security Chatbot widget */}
      <SecurityBot
        currentVuln={botVulnContext}
        isOpen={botOpen}
        onOpenChange={(open) => setBotOpen(open)}
        initialPrompt={botInitialPrompt}
        onClearInitialPrompt={() => setBotInitialPrompt(null)}
      />

      {/* FEATURE 3: Cookie Consent Banner */}
      <CookieBanner />
    </div>
  );
}
