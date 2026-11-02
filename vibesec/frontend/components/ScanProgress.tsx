"use client";

import React, { useEffect, useState } from "react";

export interface ScanProgressProps {
  isVisible?: boolean;
  progress?: number;
  currentStep?: string;
  modelName?: string;
  isCompleted?: boolean;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  isVisible = false,
  progress: externalProgress,
  modelName = "qwen2.5-coder:7b",
  isCompleted = false,
}) => {
  const [internalProgress, setInternalProgress] = useState(0);
  const [activeStepIdx, setActiveStepIdx] = useState(0);

  // If parent controls progress directly, use it, otherwise run realistic simulation
  const progress = externalProgress !== undefined ? externalProgress : internalProgress;

  useEffect(() => {
    // If not visible, reset internal states and do not start timers
    if (!isVisible) {
      setInternalProgress(0);
      setActiveStepIdx(0);
      return;
    }

    if (isCompleted) {
      setInternalProgress(100);
      setActiveStepIdx(4);
      return;
    }

    // Initial starting state when scanning begins
    setInternalProgress(15);
    setActiveStepIdx(0);

    // Step progression timers
    const timer1 = setTimeout(() => {
      setInternalProgress(30);
      setActiveStepIdx(1);
    }, 1200);

    const timer2 = setTimeout(() => {
      setInternalProgress(65);
      setActiveStepIdx(2);
    }, 2800);

    const timer3 = setTimeout(() => {
      setInternalProgress(88);
      setActiveStepIdx(3);
    }, 5500);

    const timer4 = setTimeout(() => {
      setInternalProgress(98);
      setActiveStepIdx(4);
    }, 8500);

    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);
    };
  }, [isVisible, isCompleted]);

  // Sync external progress to step index if provided
  useEffect(() => {
    if (!isVisible) return;
    if (externalProgress !== undefined) {
      if (externalProgress >= 100 || isCompleted) setActiveStepIdx(4);
      else if (externalProgress >= 80) setActiveStepIdx(3);
      else if (externalProgress >= 50) setActiveStepIdx(2);
      else if (externalProgress >= 25) setActiveStepIdx(1);
      else setActiveStepIdx(0);
    }
  }, [isVisible, externalProgress, isCompleted]);

  // Return null if not visible (Requirement 4)
  if (!isVisible) {
    return null;
  }

  const steps = [
    {
      id: 1,
      title: "Code received",
      subtitle: "Payload verified & buffered",
      instant: true,
    },
    {
      id: 2,
      title: "Semgrep SAST scan complete",
      subtitle: "Static AST rules & taint paths checked",
    },
    {
      id: 3,
      title: "Ollama AI analyzing...",
      subtitle: `Powered by ${modelName}`,
    },
    {
      id: 4,
      title: "Checking npm/PyPI registry...",
      subtitle: "Detecting hallucinated packages & slopsquatting",
    },
    {
      id: 5,
      title: "Report ready!",
      subtitle: "Risk verdict & remediation generated",
    },
  ];

  return (
    <div className="w-full bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-5 shadow-sm relative overflow-hidden">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[var(--card-border)] mb-4">
        <div className="flex items-center gap-2 text-xs font-mono text-[var(--success)]">
          <span className="w-2 h-2 rounded-full bg-[var(--success)] animate-pulse"></span>
          <span className="font-bold tracking-wider">VIBESEC ACTIVE SCAN SEQUENCE</span>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)]">
          <span className="bg-[var(--bg-main)] border border-[var(--card-border)] px-2.5 py-1 rounded-md">
            Model: <b className="text-[var(--text-primary)]">{modelName}</b>
          </span>
          <span className="bg-[var(--bg-main)] border border-[var(--card-border)] px-2.5 py-1 rounded-md">
            Progress: <b className="text-[var(--accent)]">{Math.min(100, Math.round(progress))}%</b>
          </span>
        </div>
      </div>

      {/* Progress Bar (0% -> 100%) */}
      <div className="mb-5">
        <div className="w-full h-2 bg-[var(--bg-main)] rounded-full overflow-hidden border border-[var(--card-border)] p-0.5">
          <div
            className="h-full bg-gradient-to-r from-orange-500 to-amber-500 rounded-full transition-all duration-500 ease-out shadow-xs"
            style={{ width: `${Math.min(100, Math.max(5, progress))}%` }}
          ></div>
        </div>
      </div>

      {/* Animated Step-by-Step Progress */}
      <div className="space-y-2.5 font-mono text-xs">
        {steps.map((step, idx) => {
          const isDone = activeStepIdx > idx || (idx === 4 && (isCompleted || progress >= 100));
          const isCurrent = activeStepIdx === idx && !isDone;

          return (
            <div
              key={step.id}
              style={{
                animationDelay: `${idx * 200}ms`,
              }}
              className={`flex items-center justify-between p-3 rounded-lg border transition-all duration-200 ${
                isDone
                  ? "bg-[var(--success)]/10 border-[var(--success)]/30 text-[var(--success)]"
                  : isCurrent
                  ? "bg-[var(--accent)]/10 border-[var(--accent)] text-[var(--text-primary)] shadow-xs ring-1 ring-[var(--accent)]/40"
                  : "bg-[var(--bg-main)] border-[var(--card-border)] text-[var(--text-secondary)] opacity-60"
              }`}
            >
              <div className="flex items-center gap-3">
                {/* Step Status Icon */}
                <div className="shrink-0">
                  {isDone ? (
                    <span className="w-5 h-5 rounded-full bg-[var(--success)] text-white flex items-center justify-center font-bold text-xs">
                      ✓
                    </span>
                  ) : isCurrent ? (
                    <span className="w-5 h-5 rounded-full border-2 border-[var(--accent)] border-t-transparent animate-spin flex items-center justify-center"></span>
                  ) : (
                    <span className="w-5 h-5 rounded-full border border-[var(--card-border)] text-[var(--text-secondary)] flex items-center justify-center text-[10px]">
                      {step.id}
                    </span>
                  )}
                </div>

                {/* Step Labels */}
                <div>
                  <div className="font-semibold flex items-center gap-2">
                    <span>
                      {isDone ? `✓ ${step.title}` : isCurrent ? `⟳ ${step.title}` : `Step ${step.id}: ${step.title}`}
                    </span>
                  </div>
                  <div className="text-[10px] text-[var(--text-secondary)] mt-0.5">
                    {step.subtitle}
                  </div>
                </div>
              </div>

              {/* Status Badge */}
              <div className="text-[10px] font-bold uppercase tracking-wider shrink-0 pl-2">
                {isDone ? (
                  <span className="text-[var(--success)]">Complete</span>
                ) : isCurrent ? (
                  <span className="text-[var(--accent)] animate-pulse">Running...</span>
                ) : (
                  <span className="text-[var(--text-secondary)]">Pending</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
