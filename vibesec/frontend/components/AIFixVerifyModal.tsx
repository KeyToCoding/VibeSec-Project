import React, { useState, useEffect, useRef } from "react";
import { Vulnerability, PatchProposalResponse, PatchVerificationResponse, VerificationState } from "../types";
import { getApiUrl, getApiHeaders } from "../config";

export interface AIFixVerifyModalProps {
  isOpen: boolean;
  onClose: () => void;
  vulnerability: Vulnerability | null;
  codeContext?: string;
  language?: string;
  filename?: string;
  onApplyFixToEditor?: (fixedCode: string) => void;
}

type StepState = "initial" | "generating" | "review" | "verifying" | "result";

export const AIFixVerifyModal: React.FC<AIFixVerifyModalProps> = ({
  isOpen,
  onClose,
  vulnerability,
  codeContext = "",
  language = "python",
  filename = "snippet",
  onApplyFixToEditor,
}) => {
  const [step, setStep] = useState<StepState>("initial");
  const [isEditing, setIsEditing] = useState(false);
  const [viewMode, setViewMode] = useState<"side-by-side" | "unified-diff">("side-by-side");
  const [userApproved, setUserApproved] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Proposal & Verification Data
  const [proposal, setProposal] = useState<PatchProposalResponse | null>(null);
  const [editablePatchCode, setEditablePatchCode] = useState("");
  const [verification, setVerification] = useState<PatchVerificationResponse | null>(null);
  const [copied, setCopied] = useState(false);

  // In-flight abort controller
  const abortControllerRef = useRef<AbortController | null>(null);

  // Reset state when opening a new vulnerability
  useEffect(() => {
    if (isOpen && vulnerability) {
      setStep("initial");
      setIsEditing(false);
      setUserApproved(false);
      setErrorMessage(null);
      setProposal(null);
      setVerification(null);
      setEditablePatchCode("");
    }
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [isOpen, vulnerability]);

  if (!isOpen || !vulnerability) return null;

  // Resolve active source code to pass to the model
  const activeCode = codeContext || vulnerability.code_snippet || "";

  // 1. Propose Patch Handler
  const handleGeneratePatch = async () => {
    setErrorMessage(null);
    setStep("generating");

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const response = await fetch(getApiUrl("/api/remediate/propose-patch"), {
        method: "POST",
        headers: getApiHeaders({ "Content-Type": "application/json", Accept: "application/json" }),
        body: JSON.stringify({
          vulnerability,
          code: activeCode,
          language: language || "python",
          filename: filename || vulnerability.file || "snippet",
        }),
        signal: controller.signal,
      });

      const data: PatchProposalResponse = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to generate patch from AI provider.");
      }

      setProposal(data);
      setEditablePatchCode(data.patched_code || "");
      setStep("review");
    } catch (err: any) {
      if (err.name === "AbortError") {
        setStep("initial");
        return;
      }
      setErrorMessage(err.message || "Could not generate patch. Ensure AI provider (Gemini / Ollama) is configured and active.");
      setStep("initial");
    } finally {
      abortControllerRef.current = null;
    }
  };

  // 2. Verify Patch Handler (requires explicit user approval)
  const handleVerifyPatch = async () => {
    if (!userApproved) {
      setErrorMessage("Please confirm explicit user approval by checking the box before proceeding.");
      return;
    }

    setErrorMessage(null);
    setStep("verifying");

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const response = await fetch(getApiUrl("/api/remediate/verify-patch"), {
        method: "POST",
        headers: getApiHeaders({ "Content-Type": "application/json", Accept: "application/json" }),
        body: JSON.stringify({
          original_code: activeCode,
          patched_code: editablePatchCode,
          vulnerability,
          language: language || "python",
          filename: filename || vulnerability.file || "snippet",
          user_approved: true,
        }),
        signal: controller.signal,
      });

      const data: PatchVerificationResponse = await response.json();

      if (!response.ok && !data.verification_state) {
        throw new Error(data.error || "Verification engine failed.");
      }

      setVerification(data);
      setStep("result");
    } catch (err: any) {
      if (err.name === "AbortError") {
        setStep("review");
        return;
      }
      setErrorMessage(err.message || "Verification failed. Check backend logs.");
      setStep("review");
    } finally {
      abortControllerRef.current = null;
    }
  };

  const handleCancelRequest = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  };

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-[#ef4444]/15 text-[#ef4444] border-[#ef4444]/30";
      case "high":
        return "bg-[#f97316]/15 text-[#f97316] border-[#f97316]/30";
      case "medium":
        return "bg-[#f59e0b]/15 text-[#f59e0b] border-[#f59e0b]/30";
      case "low":
        return "bg-[#3b82f6]/15 text-[#3b82f6] border-[#3b82f6]/30";
      default:
        return "bg-[#10b981]/15 text-[#10b981] border-[#10b981]/30";
    }
  };

  const getVerificationStateBadge = (state: VerificationState) => {
    switch (state) {
      case "FIX VERIFIED BY AVAILABLE CHECKS":
        return {
          bg: "bg-[#10b981]/15 text-[#10b981] border-[#10b981]/40",
          icon: "🛡️",
          title: "FIX VERIFIED BY AVAILABLE CHECKS",
          desc: "Target vulnerability rules no longer trigger in the isolated retest sandbox.",
        };
      case "STILL DETECTED":
        return {
          bg: "bg-[#f97316]/15 text-[#f97316] border-[#f97316]/40",
          icon: "⚠️",
          title: "STILL DETECTED",
          desc: "The vulnerability rule still triggered on the retested patch.",
        };
      case "VERIFICATION FAILED":
      default:
        return {
          bg: "bg-[#ef4444]/15 text-[#ef4444] border-[#ef4444]/40",
          icon: "❌",
          title: "VERIFICATION FAILED",
          desc: "Syntax validation failed or verification encountered an error.",
        };
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-[var(--card-bg)] border border-[var(--card-border)] rounded-2xl shadow-2xl overflow-hidden my-6 flex flex-col max-h-[90vh]">
        {/* MODAL HEADER */}
        <div className="px-6 py-4 border-b border-[var(--card-border)] flex items-center justify-between bg-[var(--bg-main)]/60">
          <div className="flex items-center gap-3">
            <span className="text-xl p-2 rounded-xl bg-[var(--accent)]/15 border border-[var(--accent)]/30 text-[var(--accent)]">
              ⚡
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-[var(--text-primary)]">
                  AI Security Copilot: Fix & Verify
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/30">
                  qwen2.5-coder:7b
                </span>
              </div>
              <p className="text-xs text-[var(--text-secondary)]">
                Local Ollama remediation with isolated deterministic verification
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] p-1.5 rounded-lg hover:bg-[var(--card-border)]/50 transition-colors cursor-pointer text-lg"
            title="Close"
          >
            ✕
          </button>
        </div>

        {/* MODAL BODY */}
        <div className="p-6 space-y-4 overflow-y-auto flex-1 text-xs">
          {/* Target Finding Banner */}
          <div className="p-3.5 rounded-xl bg-[var(--bg-main)] border border-[var(--card-border)] space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded-md text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadgeClass(
                    vulnerability.severity
                  )}`}
                >
                  {vulnerability.severity}
                </span>
                <span className="font-bold text-sm text-[var(--text-primary)]">
                  {vulnerability.title}
                </span>
                {vulnerability.owasp && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--card-bg)] text-[var(--text-secondary)] border border-[var(--card-border)]">
                    {vulnerability.owasp}
                  </span>
                )}
                {vulnerability.rule_id && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--card-bg)] text-[var(--accent)] border border-[var(--accent)]/30">
                    {vulnerability.rule_id}
                  </span>
                )}
              </div>
              {vulnerability.line_hint && (
                <span className="text-[11px] font-mono text-[var(--text-secondary)]">
                  line {vulnerability.line_hint}
                </span>
              )}
            </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              {vulnerability.description}
            </p>
          </div>

          {/* ERROR ALERT */}
          {errorMessage && (
            <div className="p-3 rounded-xl bg-[#ef4444]/10 border border-[#ef4444]/30 text-[#ef4444] text-xs flex items-start gap-2">
              <span className="text-base select-none">⚠️</span>
              <div className="flex-1">
                <strong>Remediation Notice:</strong> {errorMessage}
              </div>
            </div>
          )}

          {/* STEP 1: INITIAL STATE (Ready to generate) */}
          {step === "initial" && (
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                  <span>Current Vulnerable Code ({language})</span>
                </div>
                <div className="bg-[#0d0d1a] border border-[#ef4444]/30 rounded-xl p-3 overflow-x-auto font-mono text-xs max-h-56">
                  <pre className="text-zinc-300 whitespace-pre">
                    <code>{activeCode || "No code snippet available."}</code>
                  </pre>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[var(--accent)]/5 border border-[var(--accent)]/20 space-y-2">
                <h4 className="font-bold text-xs text-[var(--accent)] flex items-center gap-1.5">
                  <span>🤖</span>
                  <span>How AI Fix & Verify Works</span>
                </h4>
                <ul className="text-xs text-[var(--text-secondary)] space-y-1 list-disc list-inside">
                  <li>Ollama (<code className="text-[var(--accent)]">qwen2.5-coder:7b</code>) analyzes the vulnerability and scanner evidence to craft a secure patch.</li>
                  <li>You review the side-by-side diff and can edit the code directly.</li>
                  <li>No files or git repos are ever silently modified: changes require explicit approval.</li>
                  <li>Deterministic scanner rules rerun in an isolated sandbox to verify the fix.</li>
                </ul>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl bg-[var(--bg-main)] hover:bg-[var(--card-border)] text-[var(--text-primary)] text-xs font-semibold border border-[var(--card-border)] transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleGeneratePatch}
                  className="flex items-center gap-2 px-5 py-2 rounded-xl bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-bold shadow-md transition-all cursor-pointer"
                >
                  <span>⚡</span>
                  <span>Generate Secure Patch</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 2: GENERATING (Loading state with abort) */}
          {step === "generating" && (
            <div className="py-12 text-center space-y-4">
              <div className="inline-block animate-spin text-3xl">⚙️</div>
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-[var(--text-primary)]">
                  Generating Secure Patch with Local Ollama...
                </h4>
                <p className="text-xs text-[var(--text-secondary)]">
                  Analyzing flaw context with <code className="text-[var(--accent)] font-mono">qwen2.5-coder:7b</code>
                </p>
              </div>
              <button
                type="button"
                onClick={handleCancelRequest}
                className="px-3.5 py-1.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xs font-medium border border-[var(--card-border)] cursor-pointer"
              >
                Cancel Request
              </button>
            </div>
          )}

          {/* STEP 3: REVIEW & EDIT PATCH */}
          {step === "review" && proposal && (
            <div className="space-y-4">
              {/* Explanation card */}
              <div className="p-3.5 rounded-xl bg-[var(--bg-main)] border border-[var(--card-border)] space-y-1.5">
                <div className="flex items-center justify-between text-xs font-bold text-[var(--text-primary)]">
                  <span className="flex items-center gap-1.5 text-[var(--accent)]">
                    <span>💡</span>
                    <span>Remediation Rationale ({proposal.model_used || "Ollama"})</span>
                  </span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setViewMode("side-by-side")}
                      className={`px-2.5 py-1 rounded-md text-[10px] font-semibold border transition-colors cursor-pointer ${
                        viewMode === "side-by-side"
                          ? "bg-[var(--accent)] text-white border-[var(--accent)]"
                          : "bg-[var(--card-bg)] text-[var(--text-secondary)] border-[var(--card-border)]"
                      }`}
                    >
                      Side-by-Side
                    </button>
                    <button
                      type="button"
                      onClick={() => setViewMode("unified-diff")}
                      className={`px-2.5 py-1 rounded-md text-[10px] font-semibold border transition-colors cursor-pointer ${
                        viewMode === "unified-diff"
                          ? "bg-[var(--accent)] text-white border-[var(--accent)]"
                          : "bg-[var(--card-bg)] text-[var(--text-secondary)] border-[var(--card-border)]"
                      }`}
                    >
                      Unified Diff
                    </button>
                  </div>
                </div>
                <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                  {proposal.explanation}
                </p>
                {proposal.changes_summary && proposal.changes_summary.length > 0 && (
                  <div className="pt-1 flex flex-wrap gap-1.5">
                    {proposal.changes_summary.map((item, i) => (
                      <span
                        key={i}
                        className="text-[10px] bg-[var(--card-bg)] text-[var(--text-primary)] border border-[var(--card-border)] px-2 py-0.5 rounded-md"
                      >
                        ✓ {item}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* View Mode: Side-by-Side OR Unified Diff */}
              {viewMode === "side-by-side" ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                  {/* Left: Original Code */}
                  <div className="bg-[#ef4444]/5 border border-[#ef4444]/30 rounded-xl p-3 flex flex-col">
                    <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#ef4444]/20 text-[#ef4444] font-bold text-[11px]">
                      <span>🔴 Original Vulnerable Code</span>
                      <span>line {vulnerability.line_hint || 1}</span>
                    </div>
                    <div className="overflow-x-auto overflow-y-auto max-h-64 flex-1 text-zinc-300">
                      <pre className="text-xs whitespace-pre">
                        <code>{activeCode}</code>
                      </pre>
                    </div>
                  </div>

                  {/* Right: Proposed Patch */}
                  <div className="bg-[#10b981]/5 border border-[#10b981]/30 rounded-xl p-3 flex flex-col">
                    <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#10b981]/20 text-[#10b981] font-bold text-[11px]">
                      <span>🟢 Proposed Secure Patch</span>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => setIsEditing(!isEditing)}
                          className="hover:underline text-[10px] text-[var(--accent)] font-semibold cursor-pointer"
                        >
                          {isEditing ? "Done Editing" : "✏️ Edit Patch"}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopyCode(editablePatchCode)}
                          className="hover:underline text-[10px] cursor-pointer"
                        >
                          {copied ? "Copied!" : "Copy"}
                        </button>
                      </div>
                    </div>
                    {isEditing ? (
                      <textarea
                        value={editablePatchCode}
                        onChange={(e) => setEditablePatchCode(e.target.value)}
                        className="w-full flex-1 max-h-64 p-2 font-mono text-xs rounded-lg bg-[#0d0d1a] border border-[#10b981]/40 text-[#10b981] focus:outline-none focus:border-[var(--accent)] resize-y"
                        rows={10}
                      />
                    ) : (
                      <div className="overflow-x-auto overflow-y-auto max-h-64 flex-1 text-[#10b981]">
                        <pre className="text-xs whitespace-pre">
                          <code>{editablePatchCode}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                /* Unified Diff View */
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex items-center justify-between text-[11px] font-bold text-[var(--text-secondary)]">
                    <span>Readable Unified Diff</span>
                    <button
                      type="button"
                      onClick={() => handleCopyCode(proposal.unified_diff || editablePatchCode)}
                      className="text-[10px] hover:underline cursor-pointer text-[var(--text-secondary)]"
                    >
                      {copied ? "Copied!" : "Copy Diff"}
                    </button>
                  </div>
                  <div className="bg-[#0d0d1a] border border-[var(--card-border)] rounded-xl p-3 max-h-64 overflow-x-auto overflow-y-auto space-y-0.5">
                    {(proposal.unified_diff || "").split("\n").map((line, idx) => {
                      let lineClass = "text-zinc-400";
                      if (line.startsWith("+") && !line.startsWith("+++")) {
                        lineClass = "bg-[#10b981]/15 text-[#10b981] font-semibold px-1 rounded-xs";
                      } else if (line.startsWith("-") && !line.startsWith("---")) {
                        lineClass = "bg-[#ef4444]/15 text-[#ef4444] font-semibold px-1 rounded-xs";
                      } else if (line.startsWith("@@")) {
                        lineClass = "text-[var(--accent)] font-bold";
                      }
                      return (
                        <div key={idx} className={lineClass}>
                          <pre className="whitespace-pre">
                            <code>{line}</code>
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Explicit User Approval Requirement Box */}
              <div className="p-4 rounded-xl bg-[var(--bg-main)] border border-[var(--accent)]/30 space-y-3">
                <div className="flex items-start gap-2.5">
                  <input
                    type="checkbox"
                    id="approve-retest-check"
                    checked={userApproved}
                    onChange={(e) => setUserApproved(e.target.checked)}
                    className="mt-0.5 w-4 h-4 rounded text-[var(--accent)] focus:ring-[var(--accent)] cursor-pointer"
                  />
                  <label htmlFor="approve-retest-check" className="text-xs leading-relaxed cursor-pointer select-none">
                    <span className="font-bold text-[var(--text-primary)] block">
                      Explicit User Approval Required
                    </span>
                    <span className="text-[var(--text-secondary)] block text-[11px]">
                      I have reviewed the proposed secure patch. I explicitly authorize applying this change to an{" "}
                      <strong className="text-[var(--text-primary)]">isolated temporary sandbox</strong> to execute
                      deterministic scanner verification rules. (Original files and git repositories will never be modified).
                    </span>
                  </label>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--card-border)]">
                  <button
                    type="button"
                    onClick={handleGeneratePatch}
                    className="text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:underline cursor-pointer"
                  >
                    🔄 Re-prompt Ollama
                  </button>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={onClose}
                      className="px-3.5 py-1.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-border)] text-[var(--text-secondary)] text-xs font-medium border border-[var(--card-border)] cursor-pointer transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      disabled={!userApproved}
                      onClick={handleVerifyPatch}
                      className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
                        userApproved
                          ? "bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white shadow-md cursor-pointer"
                          : "bg-[var(--card-border)] text-zinc-500 cursor-not-allowed"
                      }`}
                    >
                      <span>🛡️</span>
                      <span>Approve & Verify in Sandbox</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* STEP 4: VERIFYING (Running deterministic rules in sandbox) */}
          {step === "verifying" && (
            <div className="py-12 text-center space-y-4">
              <div className="inline-block animate-spin text-3xl">🛡️</div>
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-[var(--text-primary)]">
                  Testing Patch in Isolated Sandbox...
                </h4>
                <p className="text-xs text-[var(--text-secondary)]">
                  Rerunning Semgrep & static SAST heuristics against modified working copy.
                </p>
                <p className="text-[11px] text-zinc-500">
                  Code execution is disabled for security. Only deterministic static rules are checked.
                </p>
              </div>
            </div>
          )}

          {/* STEP 5: VERIFICATION RESULT */}
          {step === "result" && verification && (
            <div className="space-y-4">
              {/* Prominent Verification State Pill */}
              {(() => {
                const meta = getVerificationStateBadge(verification.verification_state);
                return (
                  <div className={`p-4 rounded-xl border ${meta.bg} space-y-1`}>
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{meta.icon}</span>
                      <h4 className="font-extrabold text-sm tracking-wide">
                        {meta.title}
                      </h4>
                    </div>
                    <p className="text-xs leading-relaxed">{verification.message || meta.desc}</p>
                  </div>
                );
              })()}

              {/* Before vs After Findings Evidence */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3.5 rounded-xl bg-[var(--bg-main)] border border-[var(--card-border)] space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-bold pb-1 border-b border-[var(--card-border)]">
                    <span className="text-[var(--danger)]">🔴 Findings Before Patch</span>
                    <span className="font-mono bg-[var(--card-bg)] px-2 py-0.5 rounded border border-[var(--card-border)]">
                      {verification.before_findings?.length || 1} issue(s)
                    </span>
                  </div>
                  <div className="space-y-1 font-mono text-[11px]">
                    <div className="text-[var(--text-primary)] font-semibold">
                      {vulnerability.title}
                    </div>
                    <div className="text-zinc-500">
                      Rule: {vulnerability.rule_id || "SAST Heuristic"}
                    </div>
                    {vulnerability.line_hint && (
                      <div className="text-zinc-500">Line: {vulnerability.line_hint}</div>
                    )}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-[var(--bg-main)] border border-[var(--card-border)] space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-bold pb-1 border-b border-[var(--card-border)]">
                    <span className="text-[var(--success)]">🟢 Findings After Retest</span>
                    <span className="font-mono bg-[var(--card-bg)] px-2 py-0.5 rounded border border-[var(--card-border)]">
                      {verification.remaining_issues_count || 0} issue(s)
                    </span>
                  </div>
                  <div className="space-y-1 font-mono text-[11px]">
                    {verification.verification_state === "FIX VERIFIED BY AVAILABLE CHECKS" ? (
                      <div className="text-[var(--success)] font-semibold">
                        ✓ Target vulnerability pattern eliminated!
                      </div>
                    ) : (
                      <div className="text-[var(--danger)] font-semibold">
                        ✗ Target vulnerability still detected in patched copy.
                      </div>
                    )}
                    {verification.remaining_issues && verification.remaining_issues.length > 0 && (
                      <div className="text-[var(--warning)] text-[10px]">
                        Notice: {verification.remaining_issues.length} other issues remain in file.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Mandatory Security Disclaimer Alert */}
              <div className="p-3.5 rounded-xl bg-[var(--warning)]/10 border border-[var(--warning)]/30 text-[var(--warning)] text-xs space-y-1">
                <div className="font-bold flex items-center gap-1.5 text-xs">
                  <span>⚠️</span>
                  <span>Mandatory Security Disclaimer</span>
                </div>
                <p className="text-[11px] leading-relaxed text-[var(--text-secondary)]">
                  {verification.disclaimer}
                </p>
              </div>

              {/* Final Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[var(--card-border)]">
                <button
                  type="button"
                  onClick={() => setStep("review")}
                  className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:underline cursor-pointer"
                >
                  ← Back to Review & Edit
                </button>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleCopyCode(editablePatchCode)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-main)] hover:bg-[var(--card-border)] text-[var(--text-primary)] text-xs font-semibold border border-[var(--card-border)] cursor-pointer transition-colors"
                  >
                    <span>{copied ? "✓" : "📋"}</span>
                    <span>{copied ? "Copied!" : "Copy Patched Code"}</span>
                  </button>

                  {onApplyFixToEditor && (
                    <button
                      type="button"
                      onClick={() => {
                        onApplyFixToEditor(editablePatchCode);
                        onClose();
                      }}
                      className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-bold shadow-md cursor-pointer transition-all"
                    >
                      <span>💾</span>
                      <span>Apply to Code Input</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={onClose}
                    className="px-4 py-1.5 rounded-lg bg-[var(--card-bg)] hover:bg-[var(--card-border)] text-[var(--text-primary)] text-xs font-semibold border border-[var(--card-border)] cursor-pointer"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
