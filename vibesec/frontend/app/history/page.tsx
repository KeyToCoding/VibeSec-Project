"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { VulnReport } from "../../components/VulnReport";
import { ThemeToggle } from "../../components/ThemeToggle";
import { CookieBanner } from "../../components/CookieBanner";
import { ScanReportData } from "../../types";

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

export default function HistoryPage() {
  const [scans, setScans] = useState<StoredScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanReportData | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [sortBy, setSortBy] = useState<"date" | "riskScore" | "critical">("date");
  const [selectedScanIds, setSelectedScanIds] = useState<Record<string | number, boolean>>({});

  const loadHistory = () => {
    try {
      let raw = localStorage.getItem("vibesec_scans");
      if (!raw) {
        raw = localStorage.getItem("vibesec_history");
      }
      if (raw) {
        const parsed = JSON.parse(raw);
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
            summary: item.summary,
            primary_model: item.primary_model,
            scan_time_seconds: item.scan_time_seconds,
            hallucinated_packages: item.hallucinated_packages,
            severity_counts: item.severity_counts,
          }));
          setScans(normalized);
        }
      }
    } catch (e) {
      console.error("Failed to load scan history:", e);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleClearHistory = () => {
    if (window.confirm("Are you sure you want to clear your local scan history? This action cannot be undone.")) {
      localStorage.removeItem("vibesec_scans");
      localStorage.removeItem("vibesec_history");
      setScans([]);
      setSelectedScan(null);
      setSelectedScanIds({});
    }
  };

  const handleDeleteSelected = () => {
    const remaining = scans.filter((s) => !selectedScanIds[s.id]);
    localStorage.setItem("vibesec_scans", JSON.stringify(remaining));
    localStorage.setItem("vibesec_history", JSON.stringify(remaining));
    setScans(remaining);
    setSelectedScanIds({});
  };

  const handleExportSelected = () => {
    const toExport = scans.filter((s) =>
      Object.keys(selectedScanIds).length > 0 ? selectedScanIds[s.id] : true
    );
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(toExport, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vibesec-history-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredScans = scans.filter((scan) => {
    if (!searchFilter.trim()) return true;
    const query = searchFilter.toLowerCase();
    const typeMatch = scan.type.toLowerCase().includes(query);
    const dateMatch = scan.date.toLowerCase().includes(query);
    const vulnMatch = (scan.vulnerabilities || []).some(
      (v: any) =>
        (v.title && v.title.toLowerCase().includes(query)) ||
        (v.description && v.description.toLowerCase().includes(query)) ||
        (v.owasp && v.owasp.toLowerCase().includes(query))
    );
    return typeMatch || dateMatch || vulnMatch;
  });

  const sortedScans = [...filteredScans].sort((a, b) => {
    if (sortBy === "riskScore") {
      return (b.riskScore || 0) - (a.riskScore || 0);
    }
    if (sortBy === "critical") {
      return (b.critical || 0) - (a.critical || 0);
    }
    return new Date(b.date).getTime() - new Date(a.date).getTime();
  });

  const mapToScanReportData = (scan: StoredScan): ScanReportData => {
    return {
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
        safe: scan.vulnerabilities.length === 0 ? 1 : 0,
      },
      files_scanned: scan.files,
      summary: scan.summary || `Scan ledger entry for ${scan.type}`,
      primary_model: scan.primary_model || "qwen2.5-coder:7b",
      scan_time_seconds: scan.scan_time_seconds || 1.2,
    };
  };

  return (
    <div className="min-h-screen bg-[var(--bg-main)] text-[var(--text-primary)] p-4 md:p-8 font-sans transition-colors">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header and Back Link */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[var(--card-border)]">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="px-3 py-1.5 rounded-lg bg-[var(--card-bg)] hover:bg-[var(--bg-main)] text-xs font-medium text-[var(--text-primary)] border border-[var(--card-border)] transition-colors"
            >
              ← Back to Dashboard
            </Link>
            <div>
              <h1 className="text-xl font-bold flex items-center gap-2 text-[var(--text-primary)]">
                <span>📋</span>
                <span>Scan History Ledger</span>
              </h1>
              <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                Audit history stored securely in your browser session (localStorage)
              </p>
            </div>
          </div>

          {/* Action buttons + ThemeToggle */}
          <div className="flex items-center gap-2.5">
            <ThemeToggle />

            {scans.length > 0 && (
              <button
                type="button"
                onClick={handleExportSelected}
                className="px-3.5 py-1.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold transition-colors cursor-pointer shadow-sm"
              >
                📥 Export JSON
              </button>
            )}

            {scans.length > 0 && (
              <button
                type="button"
                onClick={handleClearHistory}
                className="px-3 py-1.5 rounded-lg bg-[var(--danger)]/15 hover:bg-[var(--danger)]/25 text-[var(--danger)] border border-[var(--danger)]/30 text-xs font-medium transition-colors cursor-pointer"
              >
                Clear History
              </button>
            )}
          </div>
        </div>

        {/* Selected Scan Report Expanded View */}
        {selectedScan ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-[var(--card-bg)] border border-[var(--card-border)] p-3 rounded-xl shadow-xs">
              <button
                onClick={() => setSelectedScan(null)}
                className="text-xs text-[var(--accent)] hover:underline flex items-center gap-1 cursor-pointer font-bold"
              >
                ← Return to Scan History Table
              </button>
              <span className="text-xs text-[var(--text-secondary)] font-mono">
                Viewing scan #{selectedScan.scan_id}
              </span>
            </div>
            <VulnReport report={selectedScan} />
          </div>
        ) : (
          /* Main Table View */
          <div className="space-y-4">
            {/* Filter and Sort Toolbar */}
            {scans.length > 0 && (
              <div className="flex flex-wrap items-center justify-between gap-3 bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-3 shadow-xs">
                {/* Search / Filter bar */}
                <div className="flex-1 min-w-[240px] relative">
                  <span className="absolute left-3 top-2.5 text-xs text-[var(--text-secondary)]">🔍</span>
                  <input
                    type="text"
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    placeholder="Search by scan type, vulnerability, OWASP..."
                    className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)]"
                  />
                </div>

                {/* Sort By Dropdown */}
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-[var(--text-secondary)]">Sort By:</span>
                  <select
                    value={sortBy}
                    onChange={(e: any) => setSortBy(e.target.value)}
                    className="bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] cursor-pointer"
                  >
                    <option value="date">Date (Newest First)</option>
                    <option value="riskScore">Risk Score (Highest First)</option>
                    <option value="critical">Critical Count (Highest First)</option>
                  </select>
                </div>
              </div>
            )}

            {/* Table Container */}
            <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl overflow-hidden shadow-sm">
              {scans.length === 0 ? (
                /* Empty state with illustration */
                <div className="p-16 text-center space-y-3">
                  <div className="w-16 h-16 mx-auto rounded-full bg-[var(--bg-main)] border border-[var(--card-border)] flex items-center justify-center text-3xl shadow-inner">
                    🛡️
                  </div>
                  <h3 className="text-base font-bold text-[var(--text-primary)]">No scans yet. Run your first scan!</h3>
                  <p className="text-xs text-[var(--text-secondary)] max-w-sm mx-auto">
                    Audit Python, JavaScript, URLs, or repositories using VibeSec to track your security trajectory over time.
                  </p>
                  <div className="pt-2">
                    <Link
                      href="/"
                      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xs transition-colors"
                    >
                      <span>🚀</span>
                      <span>Start New Security Scan</span>
                    </Link>
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
                            checked={scans.length > 0 && Object.keys(selectedScanIds).length === scans.length}
                            onChange={(e) => {
                              if (e.target.checked) {
                                const all: Record<string | number, boolean> = {};
                                scans.forEach((s) => (all[s.id] = true));
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
                      {sortedScans.map((scan, idx) => {
                        const crit = scan.critical || 0;
                        const high = scan.high || 0;
                        const med = scan.medium || 0;
                        const risk = scan.riskScore || 0;
                        const isSelected = !!selectedScanIds[scan.id];

                        let riskBadge = "text-[var(--success)] bg-[var(--success)]/10";
                        if (risk > 70) riskBadge = "text-[var(--danger)] bg-[var(--danger)]/15";
                        else if (risk > 40) riskBadge = "text-[var(--accent)] bg-[var(--accent)]/15";
                        else if (risk >= 20) riskBadge = "text-amber-500 bg-amber-500/15";

                        return (
                          <tr
                            key={scan.id}
                            className={`hover:bg-[var(--bg-main)]/50 transition-colors ${
                              isSelected ? "bg-[var(--accent)]/5" : ""
                            }`}
                          >
                            <td className="p-3.5 text-center">
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={(e) => {
                                  setSelectedScanIds((prev) => ({
                                    ...prev,
                                    [scan.id]: e.target.checked,
                                  }));
                                }}
                                className="rounded accent-[var(--accent)] cursor-pointer"
                              />
                            </td>
                            <td className="p-3.5 text-[var(--text-secondary)]">{idx + 1}</td>
                            <td className="p-3.5 whitespace-nowrap text-[var(--text-primary)]">
                              {new Date(scan.date).toLocaleString([], {
                                month: "short",
                                day: "numeric",
                                hour: "2-digit",
                                minute: "2-digit",
                              })}
                            </td>
                            <td className="p-3.5 font-bold uppercase text-[var(--accent)]">
                              {scan.type}
                            </td>
                            <td className="p-3.5 text-[var(--text-secondary)]">{scan.files}</td>
                            <td className="p-3.5">
                              {crit > 0 ? (
                                <span className="px-2 py-0.5 rounded bg-[var(--danger)]/15 text-[var(--danger)] font-bold">
                                  {crit}
                                </span>
                              ) : (
                                <span className="text-[var(--text-secondary)]">0</span>
                              )}
                            </td>
                            <td className="p-3.5">
                              {high > 0 ? (
                                <span className="px-2 py-0.5 rounded bg-orange-500/15 text-orange-500 font-bold">
                                  {high}
                                </span>
                              ) : (
                                <span className="text-[var(--text-secondary)]">0</span>
                              )}
                            </td>
                            <td className="p-3.5">
                              {med > 0 ? (
                                <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-500 font-bold">
                                  {med}
                                </span>
                              ) : (
                                <span className="text-[var(--text-secondary)]">0</span>
                              )}
                            </td>
                            <td className="p-3.5">
                              <span className={`px-2 py-0.5 rounded font-bold ${riskBadge}`}>
                                {risk}
                              </span>
                            </td>
                            <td className="p-3.5 text-right space-x-2">
                              <button
                                type="button"
                                onClick={() => setSelectedScan(mapToScanReportData(scan))}
                                className="px-2.5 py-1 rounded bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--accent)] border border-[var(--card-border)] hover:border-[var(--accent)] font-medium transition-colors cursor-pointer"
                              >
                                View Report
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Bulk Selection Footer Actions */}
            {Object.keys(selectedScanIds).some((k) => selectedScanIds[k]) && (
              <div className="flex items-center justify-between bg-[var(--card-bg)] border border-[var(--accent)]/50 rounded-xl p-3 shadow-md animate-in fade-in slide-in-from-bottom-2">
                <span className="text-xs font-mono text-[var(--text-primary)]">
                  {Object.values(selectedScanIds).filter(Boolean).length} scan(s) selected
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleExportSelected}
                    className="px-3 py-1 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold cursor-pointer"
                  >
                    Export Selected
                  </button>
                  <button
                    onClick={handleDeleteSelected}
                    className="px-3 py-1 rounded-lg bg-[var(--danger)]/15 hover:bg-[var(--danger)]/25 text-[var(--danger)] border border-[var(--danger)]/30 text-xs font-medium cursor-pointer"
                  >
                    Delete Selected
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <CookieBanner />
    </div>
  );
}
