import React, { useState, useEffect } from "react";
import {
  History,
  FileText,
  ChevronRight,
  ArrowLeft,
  RefreshCw,
  Loader2,
  Calendar,
  Download,
} from "lucide-react";
import { ScanReportData } from "../types";
import { VulnReport } from "./VulnReport";
import { getApiUrl, getApiHeaders } from "../config";

interface HistoryViewProps {
  onBack: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({ onBack }) => {
  const [history, setHistory] = useState<ScanReportData[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<ScanReportData | null>(null);

  const fetchHistory = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(getApiUrl("/api/history"), {
        headers: getApiHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          setHistory(data);
          setIsLoading(false);
          return;
        }
      }
    } catch {
      // Non-blocking
    }

    // Local ledger fallback
    try {
      const localStr = localStorage.getItem("vibesec_scans") || localStorage.getItem("vibesec_history");
      if (localStr) {
        const parsed = JSON.parse(localStr);
        if (Array.isArray(parsed)) {
          setHistory(parsed);
        }
      }
    } catch {}
    setIsLoading(false);
  };

  const exportHistoryJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(history, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `vibesec-history-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  if (selectedScan) {
    return (
      <div className="space-y-4">
        <button
          onClick={() => setSelectedScan(null)}
          className="text-xs font-mono text-[#00e57a] hover:underline flex items-center gap-1.5 cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Scan Ledger</span>
        </button>
        <VulnReport report={selectedScan} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#1e2a32]">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-[#0f1316] border border-[#1e2a32] text-zinc-400 hover:text-[#00e57a] cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h2 className="text-xl font-bold font-mono text-[#d8e4ec] flex items-center gap-2">
              <History className="w-5 h-5 text-[#00e57a]" />
              Audit Ledger & Past Scans
            </h2>
            <p className="text-xs font-mono text-zinc-400 mt-0.5">
              Persistent security audit records isolated per authenticated session
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {history.length > 0 && (
            <button
              onClick={exportHistoryJson}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#00e57a]/15 text-[#00e57a] border border-[#00e57a]/30 text-xs font-mono hover:bg-[#00e57a]/25 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
          )}
          <button
            onClick={fetchHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0f1316] border border-[#1e2a32] text-xs font-mono text-zinc-300 hover:text-[#00e57a] cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      <div className="bg-[#0f1316] border border-[#1e2a32] rounded-2xl overflow-hidden shadow-2xl">
        {isLoading ? (
          <div className="p-12 text-center text-zinc-500 font-mono text-xs flex flex-col items-center gap-3">
            <Loader2 className="w-6 h-6 animate-spin text-[#00e57a]" />
            <span>Retrieving audit history from store...</span>
          </div>
        ) : history.length === 0 ? (
          <div className="p-12 text-center text-zinc-500 font-mono text-xs space-y-2">
            <FileText className="w-8 h-8 text-zinc-600 mx-auto" />
            <p>No audits registered in current session.</p>
            <button
              onClick={onBack}
              className="text-[#00e57a] hover:underline cursor-pointer"
            >
              Run an initial scan →
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0a0d0f] text-zinc-400 border-b border-[#1e2a32]">
                <tr>
                  <th className="p-4">Scan ID</th>
                  <th className="p-4">Mode</th>
                  <th className="p-4">Target / File</th>
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Findings Breakdown</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2a32]/60">
                {history.map((item, idx) => {
                  const counts = item.severity_counts || { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
                  const crit = counts.critical || 0;
                  const high = counts.high || 0;
                  const med = counts.medium || 0;
                  const total = (item.vulnerabilities || []).length;

                  return (
                    <tr
                      key={item.scan_id || idx}
                      className="hover:bg-[#141b20] transition-colors"
                    >
                      <td className="p-4 text-zinc-300 font-semibold">
                        {item.scan_id ? item.scan_id.slice(0, 14) + "..." : `#${idx + 1}`}
                      </td>
                      <td className="p-4">
                        <span className="uppercase px-2 py-0.5 rounded text-[10px] bg-zinc-800 text-zinc-300 border border-zinc-700">
                          {item.input_type || "code"}
                        </span>
                      </td>
                      <td className="p-4 text-zinc-300 max-w-xs truncate">
                        {item.target || item.target_url || item.repo_url || item.filename || "Inline Code"}
                      </td>
                      <td className="p-4 text-zinc-500 whitespace-nowrap">
                        {item.created_at ? new Date(item.created_at).toLocaleTimeString() : "Recent"}
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-1.5">
                          {crit > 0 && (
                            <span className="bg-[#dc2626]/20 text-[#dc2626] px-1.5 py-0.5 rounded text-[10px] font-bold">
                              {crit} Crit
                            </span>
                          )}
                          {high > 0 && (
                            <span className="bg-[#d97706]/20 text-[#d97706] px-1.5 py-0.5 rounded text-[10px] font-bold">
                              {high} High
                            </span>
                          )}
                          {med > 0 && (
                            <span className="bg-[#ca8a04]/20 text-[#ca8a04] px-1.5 py-0.5 rounded text-[10px] font-bold">
                              {med} Med
                            </span>
                          )}
                          {total === 0 && (
                            <span className="bg-[#16a34a]/20 text-[#16a34a] px-1.5 py-0.5 rounded text-[10px] font-bold">
                              Safe
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => setSelectedScan(item)}
                          className="text-[#00e57a] hover:underline flex items-center gap-1 ml-auto cursor-pointer"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="w-3.5 h-3.5" />
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
    </div>
  );
};
