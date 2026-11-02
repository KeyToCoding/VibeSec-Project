"use client";

import React from "react";

export type NavTab = "dashboard" | "scan" | "chat" | "history" | "contact" | "settings";

interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  mobileOpen = false,
  onMobileClose,
}) => {
  const navItems: {
    id: NavTab;
    label: string;
    icon: string;
    href: string;
    hasIndicator?: boolean;
  }[] = [
    { id: "dashboard", label: "Dashboard", icon: "🛡️", href: "/" },
    { id: "scan", label: "New Scan", icon: "🔍", href: "/#scan-panel" },
    {
      id: "chat",
      label: "AI Assistant",
      icon: "💬",
      href: "/chat",
      hasIndicator: true, // green dot indicator
    },
    { id: "history", label: "Scan History", icon: "📋", href: "/history" },
    { id: "contact", label: "Contact", icon: "👤", href: "/contact" },
    { id: "settings", label: "Settings", icon: "⚙️", href: "/#settings-panel" },
  ];

  return (
    <>
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          onClick={onMobileClose}
          className="fixed inset-0 bg-black/60 z-40 md:hidden backdrop-blur-sm"
        />
      )}

      {/* BugCrowd-styled Sidebar container (220px wide, theme-aware) */}
      <aside
        className={`sidebar fixed top-0 left-0 bottom-0 w-[220px] bg-[var(--sidebar-bg)] border-r border-[var(--card-border)] flex flex-col justify-between z-50 transition-all duration-300 md:translate-x-0 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        }`}
      >
        {/* Top: Logo & Navigation */}
        <div>
          {/* Logo Header */}
          <div className="h-16 flex items-center justify-between px-5 border-b border-[var(--card-border)]">
            <a
              href="/"
              onClick={(e) => {
                e.preventDefault();
                onTabChange("dashboard");
              }}
              className="flex items-center gap-2.5 text-decoration-none cursor-pointer"
            >
              <div className="w-8 h-8 rounded-lg bg-[var(--accent)]/15 border border-[var(--accent)]/30 flex items-center justify-center text-lg shadow-sm">
                🛡️
              </div>
              <div>
                <span className="font-bold text-lg tracking-tight text-[var(--text-primary)] block leading-none">
                  Vibe<span className="text-[var(--accent)]">Sec</span>
                </span>
                <span className="text-[10px] text-[var(--text-secondary)] font-medium block mt-1 tracking-wider uppercase">
                  Security Ops
                </span>
              </div>
            </a>

            {mobileOpen && onMobileClose && (
              <button
                type="button"
                onClick={onMobileClose}
                className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] md:hidden text-lg cursor-pointer"
              >
                ✕
              </button>
            )}
          </div>

          {/* Navigation Items (BugCrowd active state: orange left border + bg highlight) */}
          <nav className="p-3 space-y-1 mt-2">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    onTabChange(item.id);
                    if (onMobileClose) onMobileClose();
                  }}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 cursor-pointer text-left ${
                    isActive
                      ? "border-l-4 border-[var(--accent)] bg-[var(--accent)]/10 text-[var(--accent)] font-semibold shadow-sm"
                      : "border-l-4 border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--card-bg)]"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-base">{item.icon}</span>
                    <span>{item.label}</span>
                  </div>

                  {/* Green dot indicator for AI Assistant */}
                  {item.hasIndicator && (
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--success)] opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--success)]"></span>
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Badge: Ollama Engine (Minimal BugCrowd Enterprise status badge) */}
        <div className="p-4 border-t border-[var(--card-border)]">
          <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-3 text-center shadow-xs">
            <div className="flex items-center justify-center gap-2 text-xs text-[var(--text-secondary)]">
              <span className="w-2 h-2 rounded-full bg-[var(--success)] animate-pulse"></span>
              <span className="font-semibold text-[11px] text-[var(--text-primary)]">Ollama Engine</span>
            </div>
            <span className="text-[10px] text-[var(--text-secondary)] block mt-1 font-mono">
              qwen2.5-coder:7b
            </span>
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
