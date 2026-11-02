import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const backendEndpoint = `${BACKEND_URL.replace(/\/$/, "")}/api/chat`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120000);

    const response = await fetch(backendEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (err: any) {
    console.error("Error proxying /api/chat:", err);
    return NextResponse.json(
      {
        response: "⚠️ Ollama timed out. Please try again in a moment.",
        reply: "⚠️ Ollama timed out. Please try again in a moment.",
      },
      { status: 200 }
    );
  }
}
