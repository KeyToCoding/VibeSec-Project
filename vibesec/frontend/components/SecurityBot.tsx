import React, { useState, useEffect, useRef } from "react";
import { getApiUrl, getApiHeaders } from "../config";

export interface VulnContext {
  type?: string;
  severity?: string;
  line?: number | string;
  description?: string;
  fix?: string;
  owasp?: string;
}

export interface SecurityBotProps {
  currentVuln?: VulnContext | null;
  isOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  initialPrompt?: string | null;
  onClearInitialPrompt?: () => void;
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  model?: string;
  severityBadge?: string;
  timestamp: string;
  canRetry?: boolean;
  retryText?: string;
}

export const SecurityBot: React.FC<SecurityBotProps> = ({
  currentVuln,
  isOpen: controlledIsOpen,
  onOpenChange,
  initialPrompt,
  onClearInitialPrompt,
}) => {
  const [internalIsOpen, setInternalIsOpen] = useState(false);
  const isOpen = controlledIsOpen !== undefined ? controlledIsOpen : internalIsOpen;

  const setIsOpen = (val: boolean) => {
    if (onOpenChange) {
      onOpenChange(val);
    } else {
      setInternalIsOpen(val);
    }
  };

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [loadingPhase, setLoadingPhase] = useState("Connecting to model...");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const loadingRef = useRef(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Progressive loading phase timer
  useEffect(() => {
    if (!isLoading) {
      setLoadingPhase("Connecting to model...");
      return;
    }
    const t1 = setTimeout(() => setLoadingPhase("Analyzing security context..."), 3000);
    const t2 = setTimeout(() => setLoadingPhase("Synthesizing recommendations..."), 12000);
    const t3 = setTimeout(() => setLoadingPhase("Finalizing response from qwen2.5-coder:7b..."), 25000);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [isLoading]);

  const handleCancelRequest = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  // Mode detection
  const hasVuln = !!currentVuln && !!currentVuln.type;

  // Auto-open when a vulnerability is selected or passed
  useEffect(() => {
    if (currentVuln && currentVuln.type) {
      setIsOpen(true);
    }
  }, [currentVuln]);

  // Handle initialPrompt from external caller (like clicking OWASP category)
  useEffect(() => {
    if (initialPrompt) {
      setIsOpen(true);
      sendMessage(initialPrompt);
      if (onClearInitialPrompt) onClearInitialPrompt();
    }
  }, [initialPrompt]);

  // Set greeting or context-aware first message
  useEffect(() => {
    const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    if (hasVuln && currentVuln) {
      const vulnType = currentVuln.type || "Vulnerability";
      const lineStr = currentVuln.line ? ` on line ${currentVuln.line}` : "";
      const contextMsg: ChatMessage = {
        role: "assistant",
        content: `I found a ${vulnType} vulnerability${lineStr}.\nHere's what you should know:\n\n⚠️ Risk: ${
          currentVuln.description || "Attacker can exploit this vulnerability"
        }\n🔧 Fix: ${currentVuln.fix || "Use parameterized queries / secure sanitization"}\n📚 Learn: ${
          currentVuln.owasp || "OWASP Top 10"
        }\n\nWhat would you like to know more about?`,
        severityBadge: currentVuln.severity ? currentVuln.severity.toUpperCase() : "ALERT",
        timestamp: timeStr,
      };
      setMessages([contextMsg]);
    } else {
      const defaultGreeting: ChatMessage = {
        role: "assistant",
        content: `Hi! I'm VibeSec AI powered by Ollama.\nAsk me anything about code security!`,
        timestamp: timeStr,
      };
      setMessages([defaultGreeting]);
    }
  }, [currentVuln?.type, currentVuln?.line, currentVuln?.description]);

  // Auto-scroll to bottom of messages
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isLoading, isOpen]);

  const modeASuggestions = [
    "How to fix this?",
    "Show me secure code",
    "What can attacker do?",
    "Similar CVEs",
    "How to test this?",
  ];

  const modeBSuggestions = [
    "OWASP Top 10",
    "SQL Injection",
    "How to write secure code?",
    "What is XSS?",
  ];

  const activeSuggestions = hasVuln ? modeASuggestions : modeBSuggestions;

  const sendMessage = async (textToSend: string) => {
    const trimmedMessage = textToSend.trim();
    if (!trimmedMessage || loadingRef.current) return;

    loadingRef.current = true;
    const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const userMsg: ChatMessage = {
      role: "user",
      content: trimmedMessage,
      timestamp: timeStr,
    };

    const updatedHistory = [...messages, userMsg].slice(-10);
    setMessages(updatedHistory);
    setInputValue("");
    setIsLoading(true);

    const controller = new AbortController();
    abortControllerRef.current = controller;
    const timeoutId = setTimeout(() => controller.abort(), 110000);

    try {
      const response = await fetch(getApiUrl("/api/chat"), {
        method: "POST",
        headers: getApiHeaders({ "Content-Type": "application/json", "Accept": "application/json" }),
        body: JSON.stringify({
          message: trimmedMessage,
          history: updatedHistory.map((m) => ({ role: m.role, content: m.content })),
          context: hasVuln ? currentVuln : null,
        }),
        signal: controller.signal,
      });

      let data: any = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }

      if (!response.ok) {
        const detail = data.detail || data.error || data.response || data.reply;
        throw new Error(
          typeof detail === "string" && detail.trim()
            ? detail
            : `Chat API returned HTTP ${response.status}.`
        );
      }

      const replyContent = data.response || data.reply || "";
      if (typeof replyContent !== "string" || !replyContent.trim()) {
        throw new Error("The chat API returned an empty response.");
      }

      const aiReply: ChatMessage = {
        role: "assistant",
        content: replyContent.trim(),
        model: data.model || "qwen2.5-coder:7b",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev.slice(-9), aiReply]);
    } catch (err: any) {
      const isAbort = err?.name === "AbortError" && !err?.message?.toLowerCase?.().includes("timed out");
      const isTimeout =
        err?.name === "TimeoutError" ||
        err?.message?.toLowerCase?.().includes("timed out");

      let errorText = err?.message || "Unable to connect to the VibeSec AI backend.";
      if (isAbort) {
        errorText = "Request cancelled by user.";
      } else if (isTimeout) {
        errorText = "The AI request took too long. Check that Ollama is running at the configured URL, then retry with a shorter question.";
      }

      const errorMsg: ChatMessage = {
        role: "assistant",
        content: isAbort ? errorText : `VibeSec AI error: ${errorText}`,
        model: isAbort ? "cancelled" : "error",
        canRetry: !isAbort,
        retryText: trimmedMessage,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev.slice(-9), errorMsg]);
    } finally {
      clearTimeout(timeoutId);
      abortControllerRef.current = null;
      loadingRef.current = false;
      setIsLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(inputValue);
  };

  // Helper to format code blocks inside assistant messages
  const renderMessageContent = (content: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g);

    return parts.map((part, i) => {
      if (part.startsWith("```") && part.endsWith("```")) {
        const lines = part.slice(3, -3).trim().split("\n");
        const language = lines[0].match(/^[a-zA-Z0-9_-]+$/) ? lines[0] : "";
        const code = language ? lines.slice(1).join("\n") : lines.join("\n");

        return (
          <div key={i} className="my-2 rounded-lg overflow-hidden border border-[#2d2b55] bg-[#0d0d1a]">
            {language && (
              <div className="bg-[#12082a] px-3 py-1 text-[10px] text-[#8b8fa8] font-mono border-b border-[#2d2b55] flex justify-between items-center">
                <span>{language}</span>
                <button
                  type="button"
                  onClick={() => navigator.clipboard.writeText(code)}
                  className="hover:text-white transition-colors"
                >
                  Copy
                </button>
              </div>
            )}
            <pre className="p-2.5 font-mono text-xs text-[#10b981] overflow-x-auto whitespace-pre-wrap leading-relaxed">
              <code>{code}</code>
            </pre>
          </div>
        );
      }

      // Regular text formatting (inline code and bold text)
      const subParts = part.split(/(`[^`]+`)/g);
      return (
        <span key={i} className="whitespace-pre-wrap">
          {subParts.map((sub, j) => {
            if (sub.startsWith("`") && sub.endsWith("`")) {
              return (
                <code
                  key={j}
                  className="font-mono text-[11px] bg-[#0d0d1a] text-[#10b981] px-1.5 py-0.5 rounded border border-[#2d2b55]"
                >
                  {sub.slice(1, -1)}
                </code>
              );
            }
            return sub;
          })}
        </span>
      );
    });
  };

  return (
    <div className="chat-bot fixed bottom-5 right-5 z-50">
      {/* 1. FLOATING BUTTON (When closed) */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-full bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xl hover:shadow-orange-500/30 cursor-pointer transition-all duration-200 transform hover:scale-105 ${
            hasVuln ? "animate-bounce ring-4 ring-[var(--danger)]/40" : ""
          }`}
          title="Ask VibeSec AI Security Assistant"
        >
          <span className="text-base">💬</span>
          <span>Ask AI</span>
          {hasVuln && (
            <span className="w-2 h-2 rounded-full bg-[var(--danger)] animate-ping ml-0.5"></span>
          )}
        </button>
      )}

      {/* 2. CHAT PANEL (400px wide, 520px tall, BugCrowd styling) */}
      {isOpen && (
        <div className="w-[360px] sm:w-[400px] h-[520px] bg-[var(--card-bg)] border border-[var(--card-border)] rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
          {/* Header */}
          <div className="bg-[var(--card-bg)] border-b border-[var(--card-border)] p-3.5 flex items-center justify-between">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-7 h-7 rounded-lg bg-[var(--accent)]/15 border border-[var(--accent)]/30 flex items-center justify-center text-xs shrink-0 shadow-xs">
                🛡️
              </div>
              <div className="overflow-hidden">
                <div className="flex items-center gap-1.5 text-xs font-bold text-[var(--text-primary)] truncate">
                  {hasVuln ? (
                    <span className="text-[var(--danger)] flex items-center gap-1 truncate font-semibold">
                      <span>🔴</span>
                      <span className="truncate">{currentVuln?.type || "Vulnerability"} detected</span>
                    </span>
                  ) : (
                    <span>VibeSec Security AI</span>
                  )}
                </div>
                <div className="flex items-center gap-1.5 text-[10px] text-[var(--text-secondary)]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse"></span>
                  <span>qwen2.5-coder:7b</span>
                </div>
              </div>
            </div>

            <button
              onClick={() => setIsOpen(false)}
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] p-1 rounded-lg hover:bg-[var(--bg-main)] transition-colors cursor-pointer text-sm"
              title="Close chat panel"
            >
              ✕
            </button>
          </div>

          {/* Subheader banner for active vulnerability mode */}
          {hasVuln && (
            <div className="bg-[var(--danger)]/10 border-b border-[var(--danger)]/20 px-3 py-1.5 text-[10px] text-[var(--danger)] flex items-center justify-between font-mono">
              <span className="truncate">Active Context: {currentVuln?.type}</span>
              <span className="font-bold px-1.5 py-0.2 rounded bg-[var(--danger)]/20 uppercase">
                {currentVuln?.severity || "HIGH"}
              </span>
            </div>
          )}

          {/* Scrollable Message Area */}
          <div className="flex-1 overflow-y-auto p-3.5 space-y-3 bg-[var(--bg-main)]/60 text-xs">
            {messages.map((msg, idx) => {
              const isUser = msg.role === "user";
              return (
                <div
                  key={idx}
                  className={`flex flex-col ${isUser ? "items-end" : "items-start"}`}
                >
                  {/* Severity badge on AI message if present */}
                  {!isUser && msg.severityBadge && (
                    <div className="mb-1">
                      <span className="text-[9px] font-bold tracking-wider px-2 py-0.5 rounded-full bg-[var(--danger)]/15 text-[var(--danger)] border border-[var(--danger)]/30 uppercase">
                        {msg.severityBadge} SEVERITY
                      </span>
                    </div>
                  )}

                  <div
                    className={`max-w-[85%] rounded-2xl px-3.5 py-2.5 leading-relaxed ${
                      isUser
                        ? "bg-[var(--accent)] text-white rounded-br-none shadow-sm"
                        : "bg-[var(--card-bg)] text-[var(--text-primary)] border border-[var(--card-border)] rounded-bl-none shadow-xs"
                    }`}
                  >
                    {renderMessageContent(msg.content)}

                    {/* Visible 🔄 Retry button on timeout/error */}
                    {msg.canRetry && (
                      <div className="mt-2.5 pt-2 border-t border-[var(--card-border)]">
                        <button
                          type="button"
                          onClick={() => sendMessage(msg.retryText || "")}
                          disabled={isLoading}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
                        >
                          <span>🔄</span>
                          <span>Retry</span>
                        </button>
                      </div>
                    )}
                  </div>

                  <span className="text-[9px] text-[var(--text-secondary)] mt-1 px-1 font-mono">
                    {msg.timestamp}
                  </span>
                </div>
              );
            })}

            {/* Typing Dots Animation while loading */}
            {isLoading && (
              <div className="flex flex-col items-start space-y-1">
                <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-2xl rounded-bl-none px-4 py-3 flex items-center gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] animate-bounce [animation-delay:-0.3s]"></span>
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] animate-bounce [animation-delay:-0.15s]"></span>
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] animate-bounce"></span>
                  </div>
                  <span className="text-[10px] text-[var(--text-secondary)] font-mono ml-1">
                    {loadingPhase}
                  </span>
                  <button
                    type="button"
                    onClick={handleCancelRequest}
                    className="ml-2 px-1.5 py-0.5 rounded text-[9px] font-mono bg-[var(--danger)]/15 text-[var(--danger)] hover:bg-[var(--danger)]/25 border border-[var(--danger)]/30 cursor-pointer transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Suggestion Chips */}
          <div className="p-2 border-t border-[var(--card-border)] bg-[var(--card-bg)] flex items-center gap-1.5 overflow-x-auto scrollbar-none">
            {activeSuggestions.map((sug, i) => (
              <button
                key={i}
                type="button"
                onClick={() => sendMessage(sug)}
                disabled={isLoading}
                className="shrink-0 text-[10px] font-medium bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--text-secondary)] hover:text-[var(--accent)] px-2.5 py-1 rounded-md border border-[var(--card-border)] hover:border-[var(--accent)] transition-colors cursor-pointer disabled:opacity-50"
              >
                {sug}
              </button>
            ))}
          </div>

          {/* Input Box Form */}
          <form
            onSubmit={handleSubmit}
            className="p-2.5 bg-[var(--card-bg)] border-t border-[var(--card-border)] flex items-center gap-2"
          >
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder={hasVuln ? "Ask about this vulnerability..." : "Ask security question..."}
              className="flex-1 bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-3 py-2 text-xs text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)]"
              disabled={isLoading}
            />
            <button
              type="submit"
              disabled={isLoading || !inputValue.trim()}
              className="px-3.5 py-2 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white text-xs font-bold transition-colors cursor-pointer shrink-0 shadow-xs"
            >
              Send
            </button>
          </form>
        </div>
      )}
    </div>
  );
};
