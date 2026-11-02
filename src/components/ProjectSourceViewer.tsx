import React, { useState } from "react";
import {
  FolderTree,
  FileCode,
  Download,
  Check,
  Copy,
  Terminal,
  ExternalLink,
  ChevronRight,
  Folder,
} from "lucide-react";
import { getApiUrl } from "../config";

interface ProjectFileItem {
  path: string;
  category: "backend" | "frontend" | "config";
  description: string;
  code: string;
}

const PROJECT_FILES: ProjectFileItem[] = [
  {
    path: "backend/main.py",
    category: "backend",
    description: "FastAPI REST API with 5 endpoints (code, url, upload, github, health)",
    code: `# FastAPI REST entry point
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
# Endpoints for code, url, upload, github, health...`
  },
  {
    path: "backend/scanner/code_scanner.py",
    category: "backend",
    description: "Coordinates Semgrep static analysis, LLM agent, and hallucination checks",
    code: `# Code Scanner Orchestrator
async def scan_code(code: str, language: str = "python", filename: str = "snippet"):
    semgrep_findings = semgrep_scan(code, language)
    # Concurrent agent reasoning + npm/PyPI hallucination audit...`
  },
  {
    path: "backend/scanner/url_scanner.py",
    category: "backend",
    description: "Audits live URLs for CSP, HSTS, X-Frame-Options, cookies, and JS secret tokens",
    code: `# URL Web Security Scanner
async def scan_url(url: str):
    # httpx client checks HTTP headers, scripts, and tokens...`
  },
  {
    path: "backend/scanner/file_scanner.py",
    category: "backend",
    description: "Extracts ZIP/files, strictly skips node_modules/venv/.git, audits package.json",
    code: `# File & ZIP Archive Auditor
SKIPPED_DIR_PARTS = ["node_modules", ".git", "__pycache__", ".venv", "dist"]
# Audits package.json against npm registry...`
  },
  {
    path: "backend/scanner/github_scanner.py",
    category: "backend",
    description: "Traverses public GitHub tree via REST API, flags committed .env and hardcoded keys",
    code: `# GitHub Public Repository Scanner
async def scan_github(repo_url: str):
    # Tree traversal, raw content fetch, secrets audit...`
  },
  {
    path: "backend/scanner/semgrep_runner.py",
    category: "backend",
    description: "Executes Semgrep CLI static analysis with 3-line code context extraction",
    code: `# Semgrep Runner with native regex fallback
def semgrep_scan(code: str, language: str = "python"):
    # semgrep --config=auto --json --quiet with 3-line context...`
  },
  {
    path: "backend/models/llm_chain.py",
    category: "backend",
    description: "Multi-tier LLM engine: Ollama (qwen2.5-coder:7b) primary, Groq & Gemini fallbacks",
    code: `# Multi-tier LLM Inference
async def call_llm(prompt: str, task: str = "analysis"):
    # 1. Ollama local/Colab ngrok -> 2. Groq -> 3. Gemini Flash`
  },
  {
    path: "backend/models/prompts.py",
    category: "backend",
    description: "VULN_ANALYSIS_PROMPT, URL_SECURITY_PROMPT, and HALLUCINATION_PROMPT",
    code: `VULN_ANALYSIS_PROMPT = """You are an elite security researcher..."""
URL_SECURITY_PROMPT = """..."""
HALLUCINATION_PROMPT = """..."""`
  },
  {
    path: "backend/scanner/vuln_agent.py",
    category: "backend",
    description: "LLM chunk verification agent with MD5 caching and confidence filtering",
    code: `# Vulnerability Agent with MD5 deduplication cache
async def analyze_chunk(finding, code, language, filename):
    # Cache lookup, LLM call, JSON parse, false-positive pruning`
  },
  {
    path: "backend/scanner/hallucination.py",
    category: "backend",
    description: "Checks imports against registry.npmjs.org and pypi.org for Slopsquatting",
    code: `# Package Hallucination Checker
async def check_packages(code: str, language: str):
    # Asyncio.gather checks npm and PyPI for 404 nonexistent packages`
  },
  {
    path: "backend/database.py",
    category: "backend",
    description: "MongoDB connection, scan persistence, and in-memory fallback ledger",
    code: `# Database Layer
def save_scan_result(result):
    # MongoDB upsert with fallback to memory store`
  },
  {
    path: "backend/.env",
    category: "backend",
    description: "Backend environment variables (Ollama, Colab, Groq, Gemini, Mongo)",
    code: `OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:7b
MONGODB_URI=mongodb://localhost:27017/vibesec`
  },
  {
    path: "backend/requirements.txt",
    category: "backend",
    description: "Python dependencies (FastAPI, semgrep, httpx, pymongo, groq, etc.)",
    code: `fastapi==0.111.0
uvicorn==0.30.1
httpx==0.27.0
semgrep==1.77.0
pymongo==4.8.0
groq==0.9.0`
  },
  {
    path: "frontend/app/page.tsx",
    category: "frontend",
    description: "Dark terminal Next.js 14 home page with 4 scan modes and live reporting",
    code: `// Next.js 14 Cybersecurity Terminal Page
export default function Home() { ... }`
  },
  {
    path: "frontend/app/api/scan/[type]/route.ts",
    category: "frontend",
    description: "Next.js dynamic proxy route forwarding to backend with 120s timeout",
    code: `// Dynamic API route forwarding requests to BACKEND_URL
export async function POST(req: NextRequest, { params }) { ... }`
  },
  {
    path: "frontend/components/ScanInput.tsx",
    category: "frontend",
    description: "Interactive tab switcher for Code, URL, Upload, and GitHub scanning",
    code: `export const ScanInput: React.FC<ScanInputProps> = (...) => { ... }`
  },
  {
    path: "frontend/components/VulnReport.tsx",
    category: "frontend",
    description: "Severity summary cards, hallucination alerts, headers matrix, and copy fix buttons",
    code: `export const VulnReport: React.FC<VulnReportProps> = (...) => { ... }`
  },
  {
    path: "frontend/components/ScanProgress.tsx",
    category: "frontend",
    description: "Multi-stage animated progress bar with active model indicator",
    code: `export const ScanProgress: React.FC<ScanProgressProps> = (...) => { ... }`
  },
  {
    path: "frontend/app/history/page.tsx",
    category: "frontend",
    description: "MongoDB audit history browser and detailed report modal view",
    code: `export default function HistoryPage() { ... }`
  },
  {
    path: "frontend/.env.local",
    category: "frontend",
    description: "Frontend environment config (BACKEND_URL=http://localhost:8000)",
    code: `BACKEND_URL=http://localhost:8000
NEXT_PUBLIC_APP_NAME=VibeSec`
  }
];

export const ProjectSourceViewer: React.FC = () => {
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [copied, setCopied] = useState(false);

  const current = PROJECT_FILES[selectedIdx];

  const handleCopy = () => {
    navigator.clipboard.writeText(current.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#1e2a32]">
        <div>
          <h2 className="text-xl font-bold font-mono text-[#d8e4ec] flex items-center gap-2">
            <FolderTree className="w-5 h-5 text-[#00e57a]" />
            NIELIT Major Project Code Repository (20 Files)
          </h2>
          <p className="text-xs font-mono text-zinc-400 mt-0.5">
            Complete FastAPI (Python) backend + Next.js 14 frontend by Kartikey Vishwakarma
          </p>
        </div>

        <a
          href={getApiUrl("/api/download-project-zip")}
          download="vibesec-nielit-project.zip"
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#00e57a] text-[#0a0d0f] font-mono font-bold text-xs shadow-[0_0_15px_rgba(0,229,122,0.3)] hover:bg-[#00ff88] transition-all cursor-pointer"
        >
          <Download className="w-4 h-4" />
          <span>Download Complete Project ZIP</span>
        </a>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* File Tree Navigator */}
        <div className="lg:col-span-4 bg-[#0f1316] border border-[#1e2a32] rounded-2xl p-4 space-y-2 max-h-[600px] overflow-y-auto">
          <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider px-2 pb-1 border-b border-[#1e2a32]">
            Project Tree (20 Source Files)
          </div>

          <div className="pt-2 space-y-1">
            {PROJECT_FILES.map((f, idx) => (
              <button
                key={f.path}
                onClick={() => setSelectedIdx(idx)}
                className={`w-full text-left px-3 py-2 rounded-lg font-mono text-xs flex items-center gap-2 transition-all cursor-pointer ${
                  selectedIdx === idx
                    ? "bg-[#1e2a32] text-[#00e57a] border border-[#00e57a]/30 font-semibold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-[#141b20]"
                }`}
              >
                <FileCode className={`w-3.5 h-3.5 shrink-0 ${selectedIdx === idx ? "text-[#00e57a]" : "text-zinc-500"}`} />
                <span className="truncate">{f.path}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Code Previewer */}
        <div className="lg:col-span-8 bg-[#0f1316] border border-[#1e2a32] rounded-2xl overflow-hidden shadow-2xl">
          <div className="bg-[#0a0d0f] px-4 py-3 border-b border-[#1e2a32] flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-[#d8e4ec]">
                  {current.path}
                </span>
                <span className="text-[10px] font-mono uppercase bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded">
                  {current.category}
                </span>
              </div>
              <p className="text-[11px] font-mono text-zinc-400 mt-0.5">
                {current.description}
              </p>
            </div>

            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1e2a32] hover:bg-[#283842] text-zinc-300 text-xs font-mono cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#00e57a]" />
                  <span className="text-[#00e57a]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>

          <div className="p-4 bg-[#0a0d0f] overflow-x-auto max-h-[500px]">
            <pre className="font-mono text-xs text-[#00e57a]/90 leading-relaxed">
              <code>{current.code}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
