"use client";

import React, { useEffect, useState, useMemo } from "react";

export interface ScanHistoryItem {
  id?: string | number;
  date?: string;
  created_at?: string;
  type?: string;
  input_type?: string;
  files?: number;
  files_scanned?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  severity_counts?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    safe?: number;
  };
  riskScore?: number;
  vulnerabilities?: any[];
}

export interface TrendChartProps {
  data?: ScanHistoryItem[] | any[];
  scans?: ScanHistoryItem[] | any[];
  history?: ScanHistoryItem[] | any[];
  className?: string;
}

export const TrendChart: React.FC<TrendChartProps> = (props) => {
  const [localScans, setLocalScans] = useState<ScanHistoryItem[]>([]);
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  // Load scans from localStorage if no props are passed
  const loadFromStorage = () => {
    try {
      let raw = localStorage.getItem("vibesec_scans");
      if (!raw) {
        raw = localStorage.getItem("vibesec_history");
      }
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setLocalScans(parsed);
        } else {
          setLocalScans([]);
        }
      } else {
        setLocalScans([]);
      }
    } catch (e) {
      console.error("Failed to load scans from localStorage for TrendChart", e);
      setLocalScans([]);
    }
  };

  useEffect(() => {
    // Only listen and load from storage if parent didn't supply props
    if (!props.data && !props.scans && !props.history) {
      loadFromStorage();
      window.addEventListener("focus", loadFromStorage);
      return () => window.removeEventListener("focus", loadFromStorage);
    }
  }, [props.data, props.scans, props.history]);

  // Normalize whichever data source is available
  const rawData = props.data || props.scans || props.history || localScans;

  const chartData = useMemo(() => {
    if (!Array.isArray(rawData) || rawData.length === 0) {
      return [];
    }

    const normalized: ScanHistoryItem[] = rawData.map((item: any, i: number) => {
      // Ensure strictly valid numeric values
      const crit = Number(item.critical ?? item.severity_counts?.critical ?? 0) || 0;
      const high = Number(item.high ?? item.severity_counts?.high ?? 0) || 0;
      const med = Number(item.medium ?? item.severity_counts?.medium ?? 0) || 0;
      const low = Number(item.low ?? item.severity_counts?.low ?? 0) || 0;
      const risk =
        Number(item.riskScore) ||
        crit * 10 + high * 5 + med * 2;

      const dateStr = item.date || item.created_at || item.timestamp || new Date().toISOString();

      return {
        id: item.id || item.scan_id || `scan-${i}`,
        date: dateStr,
        type: item.type || item.input_type || "code",
        critical: crit,
        high: high,
        medium: med,
        low: low,
        riskScore: risk,
        files: Number(item.files || item.files_scanned || 1) || 1,
      };
    });

    // Take the most recent 8 scans and order chronologically (oldest to newest, left-to-right)
    return normalized.slice(0, 8).reverse();
  }, [rawData]);

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return "Recent";
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return String(dateStr);
      const m = d.getMonth() + 1;
      const day = d.getDate();
      const hh = d.getHours().toString().padStart(2, "0");
      const mm = d.getMinutes().toString().padStart(2, "0");
      return `${m}/${day} ${hh}:${mm}`;
    } catch {
      return "Scan";
    }
  };

  // 4. Fallback: if data is empty, show "No scan data yet" message instead of blank chart
  if (!chartData || chartData.length === 0) {
    return (
      <div
        style={{ minHeight: 250 }}
        className={`bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-sm flex flex-col items-center justify-center min-h-[250px] w-full text-center transition-all ${
          props.className || ""
        }`}
      >
        <div className="w-12 h-12 rounded-xl bg-[var(--accent)]/10 text-[var(--accent)] flex items-center justify-center text-2xl mb-3 shadow-xs">
          📈
        </div>
        <h4 className="text-sm font-bold text-[var(--text-primary)] mb-1">
          No scan data yet
        </h4>
        <p className="text-xs text-[var(--text-secondary)] max-w-sm">
          Run your first security scan to see vulnerability severity trends plotted over time.
        </p>
      </div>
    );
  }

  // Maximum count for Y-axis scaling (minimum scale of 5)
  const maxVulnCount = Math.max(
    5,
    ...chartData.map((s) => (s.critical || 0) + (s.high || 0) + (s.medium || 0))
  );

  // Y-axis markers (Top, Mid, Bottom)
  const yAxisTicks = [maxVulnCount, Math.round(maxVulnCount / 2), 0];

  // Explicit pixel height for the plotting canvas area to avoid flex percentage height collapse
  const BAR_CANVAS_HEIGHT = 150; // px

  return (
    <div
      style={{ minHeight: 250 }}
      className={`bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-5 shadow-sm space-y-4 w-full min-h-[250px] transition-all ${
        props.className || ""
      }`}
    >
      {/* Header and Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[var(--card-border)]">
        <div>
          <h3 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <span>📈</span>
            <span>Severity Trend History</span>
          </h3>
          <p className="text-[11px] text-[var(--text-secondary)]">
            Vulnerability severity breakdown across last {chartData.length} scans
          </p>
        </div>

        {/* Legend with HARDCODED series colors */}
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
            <span
              className="w-2.5 h-2.5 rounded-xs"
              style={{ backgroundColor: "#ef4444" }}
            ></span>
            <span className="text-[var(--text-primary)] font-medium">Critical</span>
          </span>
          <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
            <span
              className="w-2.5 h-2.5 rounded-xs"
              style={{ backgroundColor: "#f97316" }}
            ></span>
            <span className="text-[var(--text-primary)] font-medium">High</span>
          </span>
          <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
            <span
              className="w-2.5 h-2.5 rounded-xs"
              style={{ backgroundColor: "#f59e0b" }}
            ></span>
            <span className="text-[var(--text-primary)] font-medium">Medium</span>
          </span>
          <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
            <span
              className="w-2.5 h-2.5 rounded-xs"
              style={{ backgroundColor: "#10b981" }}
            ></span>
            <span className="text-[var(--text-primary)] font-medium">Clean</span>
          </span>
        </div>
      </div>

      {/* Chart Canvas Container — explicit height 200px */}
      <div
        className="w-full flex gap-3 select-none relative"
        style={{ height: 200, width: "100%" }}
      >
        {/* Y Axis Numbers */}
        <div
          className="flex flex-col justify-between text-[10px] font-mono text-[var(--text-secondary)] pr-2 border-r border-[var(--card-border)] select-none shrink-0"
          style={{ height: BAR_CANVAS_HEIGHT }}
        >
          {yAxisTicks.map((tick, i) => (
            <span key={i} className="text-right leading-none">
              {tick}
            </span>
          ))}
        </div>

        {/* Chart Plot Area with Grid Lines */}
        <div className="flex-1 relative flex flex-col justify-between h-full">
          {/* Horizontal gridlines */}
          <div
            className="absolute left-0 right-0 top-0 flex flex-col justify-between pointer-events-none opacity-25"
            style={{ height: BAR_CANVAS_HEIGHT }}
          >
            <div className="border-b border-dashed border-[var(--card-border)] w-full"></div>
            <div className="border-b border-dashed border-[var(--card-border)] w-full"></div>
            <div className="border-b border-solid border-[var(--card-border)] w-full"></div>
          </div>

          {/* SVG Trend Line Overlay connecting total counts */}
          <svg
            className="absolute left-0 right-0 top-0 w-full pointer-events-none overflow-visible"
            style={{ height: BAR_CANVAS_HEIGHT }}
          >
            {chartData.length > 1 && (
              <>
                <polyline
                  fill="none"
                  stroke="#f97316"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeDasharray="4 3"
                  className="opacity-70"
                  points={chartData
                    .map((scan, i) => {
                      const total = (scan.critical || 0) + (scan.high || 0) + (scan.medium || 0);
                      const xPercent = ((i + 0.5) / chartData.length) * 100;
                      const y = BAR_CANVAS_HEIGHT - Math.round((total / maxVulnCount) * (BAR_CANVAS_HEIGHT - 12)) - 6;
                      return `${xPercent}%,${y}`;
                    })
                    .join(" ")}
                />
                {chartData.map((scan, i) => {
                  const total = (scan.critical || 0) + (scan.high || 0) + (scan.medium || 0);
                  const xPercent = `${((i + 0.5) / chartData.length) * 100}%`;
                  const y = BAR_CANVAS_HEIGHT - Math.round((total / maxVulnCount) * (BAR_CANVAS_HEIGHT - 12)) - 6;
                  return (
                    <circle
                      key={i}
                      cx={xPercent}
                      cy={y}
                      r="3.5"
                      fill="#f97316"
                      stroke="var(--card-bg)"
                      strokeWidth="1.5"
                    />
                  );
                })}
              </>
            )}
          </svg>

          {/* Bars Row */}
          <div
            className="w-full flex items-end justify-around gap-2 sm:gap-4 relative z-10"
            style={{ height: BAR_CANVAS_HEIGHT }}
          >
            {chartData.map((scan, idx) => {
              const crit = scan.critical || 0;
              const high = scan.high || 0;
              const med = scan.medium || 0;
              const total = crit + high + med;

              // Compute explicit pixel heights
              const critH = Math.max(crit > 0 ? 6 : 0, Math.round((crit / maxVulnCount) * BAR_CANVAS_HEIGHT));
              const highH = Math.max(high > 0 ? 6 : 0, Math.round((high / maxVulnCount) * BAR_CANVAS_HEIGHT));
              const medH = Math.max(med > 0 ? 6 : 0, Math.round((med / maxVulnCount) * BAR_CANVAS_HEIGHT));
              const isClean = total === 0;

              const isHovered = hoveredIdx === idx;

              return (
                <div
                  key={idx}
                  className="flex-1 max-w-[48px] h-full flex flex-col justify-end items-center relative group cursor-pointer"
                  onMouseEnter={() => setHoveredIdx(idx)}
                  onMouseLeave={() => setHoveredIdx(null)}
                >
                  {/* Tooltip on Hover */}
                  {isHovered && (
                    <div className="absolute bottom-full mb-2 z-40 bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-3 text-xs shadow-2xl pointer-events-none min-w-[150px] animate-in fade-in zoom-in-95">
                      <div className="font-bold text-[var(--text-primary)] text-[11px] pb-1.5 border-b border-[var(--card-border)] flex justify-between items-center">
                        <span className="uppercase text-[var(--accent)] font-mono">{scan.type}</span>
                        <span className="text-[var(--text-secondary)] font-mono">{formatDate(scan.date)}</span>
                      </div>
                      <div className="mt-2 space-y-1 text-[11px] font-mono">
                        <div className="flex justify-between items-center" style={{ color: "#ef4444" }}>
                          <span>Critical:</span>
                          <span className="font-bold">{crit}</span>
                        </div>
                        <div className="flex justify-between items-center" style={{ color: "#f97316" }}>
                          <span>High:</span>
                          <span className="font-bold">{high}</span>
                        </div>
                        <div className="flex justify-between items-center" style={{ color: "#f59e0b" }}>
                          <span>Medium:</span>
                          <span className="font-bold">{med}</span>
                        </div>
                        <div className="flex justify-between items-center text-[var(--text-secondary)] pt-1.5 border-t border-[var(--card-border)]">
                          <span>Total Vulns:</span>
                          <span className="font-bold text-[var(--text-primary)]">{total}</span>
                        </div>
                        <div className="flex justify-between items-center text-[var(--accent)]">
                          <span>Risk Score:</span>
                          <span className="font-bold">{scan.riskScore || 0}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Top value badge when > 0 */}
                  {total > 0 && (
                    <span className="text-[9px] font-mono font-bold text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] mb-1 transition-colors">
                      {total}
                    </span>
                  )}

                  {/* Explicit-height Bar Stack */}
                  <div
                    style={{ height: `${BAR_CANVAS_HEIGHT}px` }}
                    className="w-full flex flex-col justify-end items-center"
                  >
                    <div className="w-full max-w-[36px] flex flex-col justify-end rounded-t-md overflow-hidden transition-all duration-200 group-hover:scale-105 shadow-sm">
                      {isClean ? (
                        /* Clean scan indicator (Hardcoded Emerald/Green) */
                        <div
                          style={{ height: "14px", backgroundColor: "#10b981" }}
                          className="w-full rounded-t-md flex items-center justify-center shadow-[0_0_8px_rgba(16,185,129,0.4)]"
                          title="All Clean (0 vulnerabilities)"
                        >
                          <span className="text-[8px] text-white font-bold leading-none">✓</span>
                        </div>
                      ) : (
                        <>
                          {/* Critical portion = Hardcoded Red #ef4444 */}
                          {crit > 0 && (
                            <div
                              style={{ height: `${critH}px`, backgroundColor: "#ef4444" }}
                              className="w-full transition-all duration-300 shadow-[0_0_8px_rgba(239,68,68,0.4)] rounded-t-sm"
                              title={`Critical: ${crit}`}
                            ></div>
                          )}
                          {/* High portion = Hardcoded Orange #f97316 */}
                          {high > 0 && (
                            <div
                              style={{ height: `${highH}px`, backgroundColor: "#f97316" }}
                              className="w-full transition-all duration-300 shadow-[0_0_6px_rgba(249,115,22,0.3)]"
                              title={`High: ${high}`}
                            ></div>
                          )}
                          {/* Medium portion = Hardcoded Yellow #f59e0b */}
                          {med > 0 && (
                            <div
                              style={{ height: `${medH}px`, backgroundColor: "#f59e0b" }}
                              className="w-full transition-all duration-300 shadow-[0_0_6px_rgba(245,158,11,0.3)] rounded-b-xs"
                              title={`Medium: ${med}`}
                            ></div>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* X Axis Labels Row */}
          <div className="w-full flex items-center justify-around gap-2 sm:gap-4 pt-2 border-t border-[var(--card-border)] select-none">
            {chartData.map((scan, idx) => (
              <div key={idx} className="flex-1 max-w-[48px] text-center">
                <span className="text-[10px] font-mono text-[var(--text-secondary)] block truncate">
                  {formatDate(scan.date)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
