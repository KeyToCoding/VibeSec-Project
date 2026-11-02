"use client";

import React from "react";

interface OWASPMapProps {
  detectedCategories?: string[];
  onSelectCategory?: (owaspId: string, name: string) => void;
}

interface OWASPItem {
  id: string; // A01 - A10
  name: string;
  icon: string;
  description: string;
}

const OWASP_TOP_10: OWASPItem[] = [
  { id: "A01", name: "Broken Access Control", icon: "🔐", description: "Flaws allowing unauthorized privilege escalation or horizontal data access" },
  { id: "A02", name: "Cryptographic Failures", icon: "🔑", description: "Exposure of sensitive data through weak or missing encryption algorithms" },
  { id: "A03", name: "Injection", icon: "💉", description: "SQL, command, or LDAP injection from unsanitized user supplied input" },
  { id: "A04", name: "Insecure Design", icon: "🏗️", description: "Architectural vulnerabilities and lack of threat modeling during design" },
  { id: "A05", name: "Security Misconfiguration", icon: "⚙️", description: "Default credentials, unnecessary ports, misconfigured HTTP headers" },
  { id: "A06", name: "Vulnerable Components", icon: "📦", description: "Outdated packages or hallucinated dependencies with known CVEs" },
  { id: "A07", name: "Auth Failures", icon: "👤", description: "Weak session tokens, brute-force vulnerabilities, missing MFA" },
  { id: "A08", name: "Data Integrity Failures", icon: "🔗", description: "Insecure deserialization or untrusted CI/CD code pipelines" },
  { id: "A09", name: "Logging Failures", icon: "📋", description: "Insufficient audit logs or failure to detect intrusions in real-time" },
  { id: "A10", name: "SSRF", icon: "🌐", description: "Server-Side Request Forgery forcing backend requests to private resources" },
];

export const OWASPMap: React.FC<OWASPMapProps> = ({
  detectedCategories = [],
  onSelectCategory,
}) => {
  // Normalize detected categories
  const isDetected = (item: OWASPItem) => {
    return detectedCategories.some((cat) => {
      if (!cat) return false;
      const upper = cat.toUpperCase();
      return (
        upper.includes(item.id) ||
        upper.includes(item.name.toUpperCase()) ||
        (item.id === "A03" && upper.includes("INJECTION")) ||
        (item.id === "A06" && (upper.includes("PACKAGE") || upper.includes("COMPONENT") || upper.includes("DEPENDENCY"))) ||
        (item.id === "A10" && upper.includes("SSRF"))
      );
    });
  };

  return (
    <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-5 shadow-sm space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[var(--card-border)]">
        <div>
          <h3 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2">
            <span>🛡️</span>
            <span>OWASP Top 10 Coverage Matrix</span>
          </h3>
          <p className="text-[11px] text-[var(--text-secondary)] mt-0.5">
            Click any category to consult VibeSec AI regarding mitigation and attack vectors
          </p>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono">
          <span className="flex items-center gap-1 text-[var(--success)] font-medium">
            <span className="w-2 h-2 rounded-full bg-[var(--success)]"></span>
            <span>Detected</span>
          </span>
          <span className="flex items-center gap-1 text-[var(--text-secondary)]">
            <span className="w-2 h-2 rounded-full bg-slate-400"></span>
            <span>Safe / Not Found</span>
          </span>
        </div>
      </div>

      {/* 5x2 grid on lg screens, 2-3 cols on smaller */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {OWASP_TOP_10.map((item) => {
          const detected = isDetected(item);

          return (
            <div
              key={item.id}
              onClick={() => {
                if (onSelectCategory) {
                  onSelectCategory(
                    item.id,
                    `Tell me about OWASP ${item.id} (${item.name}) vulnerabilities, typical attack vectors, and how to fix them in code.`
                  );
                }
              }}
              className={`p-3 rounded-lg border transition-all duration-150 cursor-pointer flex flex-col justify-between group ${
                detected
                  ? "bg-[var(--success)]/10 border-[var(--success)] shadow-xs hover:scale-[1.02]"
                  : "bg-[var(--bg-main)] border-[var(--card-border)] hover:border-[var(--accent)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-bold text-[var(--text-primary)] flex items-center gap-1.5">
                    <span className="text-sm">{item.icon}</span>
                    <span>{item.id}</span>
                  </span>
                  {detected ? (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-[var(--success)] text-white tracking-wider animate-pulse">
                      DETECTED
                    </span>
                  ) : (
                    <span className="text-[9px] font-mono text-[var(--text-secondary)]">
                      CLEAN
                    </span>
                  )}
                </div>

                <div className={`text-xs font-semibold leading-tight mb-1 ${detected ? "text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`}>
                  {item.name}
                </div>
              </div>

              <div className="mt-2 pt-2 border-t border-[var(--card-border)]/80 flex items-center justify-between text-[10px] text-[var(--text-secondary)] group-hover:text-[var(--accent)]">
                <span className="font-medium">Ask AI</span>
                <span>→</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
