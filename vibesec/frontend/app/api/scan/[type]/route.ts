import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export async function POST(
  req: NextRequest,
  { params }: { params: { type: string } }
) {
  const scanType = params.type;
  const validTypes = ["code", "url", "upload", "github"];

  if (!validTypes.includes(scanType)) {
    return NextResponse.json(
      { error: `Invalid scan type: ${scanType}. Expected one of: ${validTypes.join(", ")}` },
      { status: 400 }
    );
  }

  const backendEndpoint = `${BACKEND_URL.replace(/\/$/, "")}/api/scan/${scanType}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120000); // 120s timeout

    let backendResponse: Response;

    if (scanType === "upload") {
      const formData = await req.formData();
      backendResponse = await fetch(backendEndpoint, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });
    } else {
      const bodyJson = await req.json();
      backendResponse = await fetch(backendEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyJson),
        signal: controller.signal,
      });
    }

    clearTimeout(timeoutId);

    const data = await backendResponse.json();
    return NextResponse.json(data, { status: backendResponse.status });
  } catch (err: any) {
    if (err.name === "AbortError") {
      return NextResponse.json(
        { error: "Scan request timed out after 120 seconds." },
        { status: 504 }
      );
    }
    console.error(`Error forwarding ${scanType} scan to backend:`, err);
    return NextResponse.json(
      {
        error: "Failed to connect to VibeSec backend.",
        details: err?.message || "Unknown error",
        backend_url: backendEndpoint,
      },
      { status: 502 }
    );
  }
}
