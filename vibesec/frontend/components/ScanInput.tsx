"use client";

import React, { useState } from "react";
import { ScanProgress } from "./ScanProgress";

export type InputMode = "code" | "url" | "upload" | "github";

interface ScanInputProps {
  onScan: (mode: InputMode, data: any) => void;
  isScanning: boolean;
}

const PRESET_SNIPPETS = {
  sqli: {
    lang: "python",
    code: `# AI-generated Flask endpoint with raw SQL string formatting
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    # VULNERABLE: Direct string interpolation into SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
`,
  },
  secrets: {
    lang: "javascript",
    code: `// AI-generated AWS S3 client with hardcoded credentials
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

// CRITICAL: Hardcoded AWS credentials in source code
const s3 = new S3Client({
  region: "us-east-1",
  credentials: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
});

export async function uploadFile(bucket, key, body) {
  return await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body }));
}
`,
  },
  hallucinated: {
    lang: "javascript",
    code: `// AI-suggested package import: package doesn't exist on npm!
// Attacker can register this unclaimed package name and achieve RCE
import { secureJwtVerify } from "jwt-super-auth-v2-guard";
import express from "express";

const app = express();

app.post("/auth", (req, res) => {
  const verified = secureJwtVerify(req.headers.authorization);
  res.json({ ok: verified });
});
`,
  },
};

export const ScanInput: React.FC<ScanInputProps> = ({ onScan, isScanning }) => {
  const [activeTab, setActiveTab] = useState<InputMode>("code");
  const [code, setCode] = useState(PRESET_SNIPPETS.sqli.code);
  const [language, setLanguage] = useState("python");
  const [url, setUrl] = useState("https://example.com");
  const [file, setFile] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState("https://github.com/");
  const [dragActive, setDragActive] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const handleSelectFile = (selectedFile: File) => {
    const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB
    if (selectedFile.size > MAX_UPLOAD_BYTES) {
      setUploadError(
        `Selected file exceeds the 100MB limit (${(selectedFile.size / (1024 * 1024)).toFixed(1)}MB). Please choose a file under 100MB.`
      );
      setFile(null);
    } else {
      setUploadError(null);
      setFile(selectedFile);
    }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;

    if (activeTab === "code") {
      onScan("code", { code, language });
    } else if (activeTab === "url") {
      onScan("url", { target_url: url });
    } else if (activeTab === "upload") {
      if (file) {
        onScan("upload", { file });
      }
    } else if (activeTab === "github") {
      onScan("github", { repo_url: githubUrl });
    }
  };

  return (
    <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-xl p-6 shadow-md hover:shadow-lg transition-all">
      {/* Title */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5 pb-4 border-b border-[var(--card-border)]">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
            <span className="text-[var(--accent)]">🛡️</span>
            <span>New Security Audit</span>
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Static SAST inspection + Ollama reasoning + supply chain hallucination check
          </p>
        </div>

        {/* Tab switcher: Code | URL | File | GitHub (BugCrowd pill style) */}
        <div className="flex items-center gap-1 bg-[var(--bg-main)] p-1 rounded-lg border border-[var(--card-border)]">
          {(
            [
              { id: "code", label: "Code", icon: "📋" },
              { id: "url", label: "URL", icon: "🔗" },
              { id: "upload", label: "File", icon: "📁" },
              { id: "github", label: "GitHub", icon: "🐙" },
            ] as const
          ).map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`relative px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-150 cursor-pointer flex items-center gap-1.5 ${
                  isActive
                    ? "bg-[var(--card-bg)] text-[var(--accent)] font-semibold shadow-xs border border-[var(--card-border)]"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--card-bg)]/50"
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* TAB 1: CODE PASTE */}
        {activeTab === "code" && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--text-secondary)] font-medium">Language:</span>
                <select
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                  className="bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-2.5 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] cursor-pointer"
                >
                  <option value="python">Python (.py)</option>
                  <option value="javascript">JavaScript (.js / .jsx)</option>
                  <option value="typescript">TypeScript (.ts / .tsx)</option>
                  <option value="php">PHP (.php)</option>
                  <option value="java">Java (.java)</option>
                  <option value="go">Go (.go)</option>
                </select>
              </div>

              {/* Preset buttons */}
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[var(--text-secondary)]">Presets:</span>
                <button
                  type="button"
                  onClick={() => {
                    setCode(PRESET_SNIPPETS.sqli.code);
                    setLanguage(PRESET_SNIPPETS.sqli.lang);
                  }}
                  className="text-[11px] bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--accent)] border border-[var(--card-border)] hover:border-[var(--accent)] px-2.5 py-1 rounded-md cursor-pointer transition-colors font-medium"
                >
                  SQL Injection
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setCode(PRESET_SNIPPETS.secrets.code);
                    setLanguage(PRESET_SNIPPETS.secrets.lang);
                  }}
                  className="text-[11px] bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--danger)] border border-[var(--card-border)] hover:border-[var(--danger)] px-2.5 py-1 rounded-md cursor-pointer transition-colors font-medium"
                >
                  Hardcoded Keys
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setCode(PRESET_SNIPPETS.hallucinated.code);
                    setLanguage(PRESET_SNIPPETS.hallucinated.lang);
                  }}
                  className="text-[11px] bg-[var(--bg-main)] hover:bg-[var(--card-bg)] text-[var(--warning)] border border-[var(--card-border)] hover:border-[var(--warning)] px-2.5 py-1 rounded-md cursor-pointer transition-colors font-medium"
                >
                  Hallucinated Pkg
                </button>
              </div>
            </div>

            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              rows={9}
              placeholder="// Paste AI-generated code here for security audit..."
              className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] focus:border-[var(--accent)] rounded-lg p-3.5 text-xs font-mono text-[var(--text-primary)] focus:outline-none resize-y selection:bg-[var(--accent)]/30"
            />
          </div>
        )}

        {/* TAB 2: WEBSITE URL */}
        {activeTab === "url" && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1.5 font-medium">
                Target Website URL
              </label>
              <input
                type="url"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] focus:border-[var(--accent)] rounded-lg px-4 py-2.5 text-xs font-mono text-[var(--text-primary)] focus:outline-none transition-colors"
              />
            </div>

            {/* Checklist of what gets scanned */}
            <div className="bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg p-3 text-xs space-y-1.5 text-[var(--text-secondary)]">
              <div className="text-[var(--text-primary)] font-semibold text-[11px] uppercase tracking-wider mb-1">
                Audit Checklist
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[var(--success)] font-bold">✓</span>
                <span>Security Headers: CSP, HSTS, X-Frame-Options, X-Content-Type</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[var(--success)] font-bold">✓</span>
                <span>SSL/TLS Certificate Validity and Expiration</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[var(--success)] font-bold">✓</span>
                <span>Cookie Security Flags: Secure, HttpOnly, SameSite</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[var(--success)] font-bold">✓</span>
                <span>OWASP Top 10 Surface Analysis & Server Header Disclosure</span>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: FILE UPLOAD */}
        {activeTab === "upload" && (
          <div className="space-y-3">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleFileDrop}
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-all bg-[var(--bg-main)] ${
                dragActive
                  ? "border-[var(--accent)] bg-[var(--accent)]/5"
                  : "border-[var(--card-border)] hover:border-[var(--accent)]"
              }`}
            >
              <input
                type="file"
                id="file-upload"
                className="hidden"
                accept=".zip,.py,.js,.jsx,.ts,.tsx,.php,.java,.go,package.json,requirements.txt"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleSelectFile(e.target.files[0]);
                  }
                }}
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center justify-center"
              >
                <span className="text-3xl mb-2">📦</span>
                <span className="text-xs font-semibold text-[var(--text-primary)]">
                  Click to browse or drag & drop project archive / file
                </span>
                <span className="text-[11px] text-[var(--text-secondary)] mt-1">
                  Supports .zip, .py, .js, .ts, .php, package.json (max 100MB)
                </span>
                {file && (
                  <span className="mt-2 text-[10px] text-[var(--success)] bg-[var(--success)]/10 px-2.5 py-0.5 rounded border border-[var(--success)]/30 font-medium">
                    Selected: {file.name} (
                    {file.size >= 1024 * 1024
                      ? `${(file.size / (1024 * 1024)).toFixed(2)} MB`
                      : `${(file.size / 1024).toFixed(1)} KB`}
                    )
                  </span>
                )}
                {uploadError && (
                  <span className="mt-2 text-[10px] text-[var(--danger)] bg-[var(--danger)]/10 px-2.5 py-1 rounded border border-[var(--danger)]/30 font-medium">
                    ⚠️ {uploadError}
                  </span>
                )}
              </label>
            </div>

            {/* node_modules skipped chip */}
            <div className="flex items-center gap-2 bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)]">
              <span className="text-[var(--success)]">🛡️</span>
              <span>node_modules, .git, and .venv are automatically skipped</span>
            </div>
          </div>
        )}

        {/* TAB 4: GITHUB */}
        {activeTab === "github" && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1.5 font-medium">
                GitHub Repository URL
              </label>
              <input
                type="url"
                required
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                className="w-full bg-[var(--bg-main)] border border-[var(--card-border)] focus:border-[var(--accent)] rounded-lg px-4 py-2.5 text-xs font-mono text-[var(--text-primary)] focus:outline-none transition-colors"
              />
            </div>

            <div className="flex items-center gap-2 bg-[var(--bg-main)] border border-[var(--card-border)] rounded-lg px-3 py-1.5 text-xs text-[var(--accent)]">
              <span>🐙</span>
              <span>Public repos only. Scans git tree via API, flags committed .env and hardcoded secrets.</span>
            </div>
          </div>
        )}

        {/* Animated Scan Progress Steps: Only renders when isScanning === true */}
        {isScanning === true && (
          <div className="pt-2">
            <ScanProgress isVisible={isScanning} modelName="qwen2.5-coder:7b" />
          </div>
        )}

        {/* SCAN NOW: BugCrowd orange primary CTA button */}
        <button
          type="submit"
          disabled={isScanning || (activeTab === "upload" && !file)}
          className={`w-full py-3 rounded-lg font-bold text-sm tracking-wider flex items-center justify-center gap-2.5 transition-all duration-200 cursor-pointer ${
            isScanning
              ? "bg-[var(--card-border)] text-[var(--text-secondary)] cursor-not-allowed"
              : "bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white shadow-md hover:shadow-orange-500/25 active:scale-[0.99]"
          }`}
        >
          {/* Status Indicator Dot: only pulses during an active scan, static otherwise */}
          <span
            className={`w-2 h-2 rounded-full transition-all duration-200 ${
              isScanning
                ? "bg-[var(--danger)] animate-pulse shadow-[0_0_8px_#ef4444]"
                : "bg-[var(--success)]"
            }`}
          ></span>
          <span>🔍</span>
          <span>{isScanning ? "Running Security Audit..." : "SCAN NOW"}</span>
        </button>
      </form>
    </div>
  );
};

export default ScanInput;
