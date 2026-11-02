"use client";

import React, { useEffect, useState } from "react";

interface RiskGaugeProps {
  critical: number;
  high: number;
  medium: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  critical = 0,
  high = 0,
  medium = 0,
}) => {
  // Score = critical*10 + high*5 + medium*2 (max 100)
  const targetScore = Math.min(100, Math.max(0, critical * 10 + high * 5 + medium * 2));
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Quick load animation
    const timer = setTimeout(() => {
      setAnimatedScore(targetScore);
    }, 50);
    return () => clearTimeout(timer);
  }, [targetScore]);

  // Color selection
  let arcColor = "#10b981"; // Green (< 20)
  let postureLabel = "LOW RISK";
  let postureBadgeClass = "bg-[#10b981]/15 text-[#10b981] border-[#10b981]/30";

  if (targetScore > 70) {
    arcColor = "#ef4444"; // Red
    postureLabel = "CRITICAL POSTURE";
    postureBadgeClass = "bg-[#ef4444]/15 text-[#ef4444] border-[#ef4444]/30";
  } else if (targetScore > 40) {
    arcColor = "#f97316"; // Orange
    postureLabel = "MODERATE RISK";
    postureBadgeClass = "bg-[#f97316]/15 text-[#f97316] border-[#f97316]/30";
  } else if (targetScore >= 20) {
    arcColor = "#f59e0b"; // Yellow
    postureLabel = "MODERATE RISK";
    postureBadgeClass = "bg-[#f59e0b]/15 text-[#f59e0b] border-[#f59e0b]/30";
  }

  // Semicircle geometry
  // Radius = 65, Center = (90, 85). Arc starts at (25, 85) to (155, 85)
  // Length of semicircle = PI * R = 3.14159 * 65 ≈ 204.2
  const arcLength = Math.PI * 65;
  const strokeDashoffset = arcLength - (animatedScore / 100) * arcLength;

  return (
    <div className="flex flex-col items-center justify-center p-5 bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl shadow-sm hover:shadow-md transition-all w-full">
      <div className="relative w-48 h-28 flex items-end justify-center overflow-hidden">
        <svg
          viewBox="0 0 180 100"
          className="w-full h-full"
        >
          {/* Background Track Arc */}
          <path
            d="M 25 85 A 65 65 0 0 1 155 85"
            fill="none"
            stroke="var(--bg-main)"
            strokeWidth="12"
            strokeLinecap="round"
          />
          {/* Subtle Outer Glow Track */}
          <path
            d="M 25 85 A 65 65 0 0 1 155 85"
            fill="none"
            stroke="var(--card-border)"
            strokeWidth="4"
            strokeLinecap="round"
          />
          {/* Progress Semicircle Arc */}
          <path
            d="M 25 85 A 65 65 0 0 1 155 85"
            fill="none"
            stroke={arcColor}
            strokeWidth="12"
            strokeDasharray={arcLength}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
            style={{
              filter: `drop-shadow(0 0 8px ${arcColor}80)`,
            }}
          />
        </svg>

        {/* Center Numbers */}
        <div className="absolute inset-x-0 bottom-1 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-extrabold font-mono text-[var(--text-primary)] leading-none tracking-tight">
            {targetScore}
          </span>
          <span className="text-[10px] font-mono tracking-wider text-[var(--text-secondary)] uppercase mt-0.5">
            RISK SCORE
          </span>
        </div>
      </div>

      {/* Posture Label below arc */}
      <div className="mt-2 text-center">
        <span
          className={`inline-block px-3 py-1 rounded-full text-xs font-bold tracking-wider uppercase border ${postureBadgeClass}`}
        >
          {postureLabel}
        </span>
      </div>

      {/* Quick weights subtitle */}
      <div className="mt-2 text-[10px] text-[var(--text-secondary)] font-mono flex items-center gap-3">
        <span>Crit ×10: <b className="text-[#ef4444]">{critical * 10}</b></span>
        <span>High ×5: <b className="text-[#f97316]">{high * 5}</b></span>
        <span>Med ×2: <b className="text-[#f59e0b]">{medium * 2}</b></span>
      </div>
    </div>
  );
};
