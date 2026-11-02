"use client";

import React, { useState, useEffect } from "react";

export const CookieBanner: React.FC = () => {
  const [show, setShow] = useState(false);
  const [isDismissing, setIsDismissing] = useState(false);

  useEffect(() => {
    try {
      const consent = localStorage.getItem("vibesec-cookies");
      if (!consent) {
        setShow(true);
      }
    } catch {
      // In case localStorage is blocked
    }
  }, []);

  const handleAccept = () => {
    try {
      localStorage.setItem("vibesec-cookies", "accepted");
    } catch {}
    setIsDismissing(true);
    setTimeout(() => setShow(false), 200);
  };

  const handleDismiss = () => {
    setIsDismissing(true);
    setTimeout(() => setShow(false), 200);
  };

  if (!show) return null;

  return (
    <div
      role="region"
      aria-label="Cookie consent"
      className={`fixed bottom-0 left-0 right-0 z-50 p-4 border-t border-[var(--card-border)] bg-[var(--card-bg)]/95 backdrop-blur-md shadow-2xl flex flex-col sm:flex-row items-center justify-between gap-4 transition-all duration-200 ${
        isDismissing ? "opacity-0 translate-y-full" : "animate-slide-up"
      }`}
    >
      <div className="flex items-center gap-3">
        <span className="text-xl">🍪</span>
        <p className="text-xs sm:text-sm text-[var(--text-secondary)] leading-relaxed">
          We use cookies to enhance your security scanning experience and analyze usage.
        </p>
      </div>

      <div className="flex items-center gap-2.5 shrink-0 w-full sm:w-auto justify-end">
        <button
          type="button"
          onClick={handleAccept}
          className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-xs sm:text-sm font-semibold hover:bg-[var(--accent-hover)] shadow-sm transition-colors cursor-pointer"
        >
          Accept All
        </button>
        <button
          type="button"
          onClick={handleDismiss}
          className="px-4 py-2 border border-[var(--card-border)] text-[var(--text-primary)] hover:border-[var(--accent)] rounded-lg text-xs sm:text-sm font-medium transition-colors cursor-pointer"
        >
          Manage Preferences
        </button>
      </div>
    </div>
  );
};

export default CookieBanner;
