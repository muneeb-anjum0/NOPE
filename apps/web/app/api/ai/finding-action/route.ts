import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { API_BASE } from "@/lib/api";

const actions = new Set(["explain", "challenge", "fix", "test", "regression_test", "patch_review"]);

async function authHeaders() {
  const token = (await cookies()).get("nope_session")?.value;
  const headers = new Headers();
  if (token) headers.set("authorization", `Bearer ${token}`);
  return headers;
}

export async function POST(request: Request) {
  const body = await request.json();
  const action = String(body.action ?? "");
  if (!actions.has(action)) {
    return NextResponse.json({ status: "Failed", message: "Unsupported finding AI action." }, { status: 400 });
  }

  const headers = await authHeaders();
  if (body.scanId && body.findingId) {
    const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(String(body.scanId))}/findings/${encodeURIComponent(String(body.findingId))}/ai-actions`, {
      method: "POST",
      headers: new Headers([["content-type", "application/json"], ...headers.entries()]),
      body: JSON.stringify({ action }),
      cache: "no-store",
    });
    const result = await response.json();
    return NextResponse.json(result, { status: response.status });
  }

  const response = await fetch(`${API_BASE}/api/findings/${action}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...Object.fromEntries(headers.entries()),
    },
    body: JSON.stringify(body.finding),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}

export async function GET(request: Request) {
  const jobId = new URL(request.url).searchParams.get("job");
  if (!jobId) {
    return NextResponse.json({ status: "Failed", message: "Missing AI action job id." }, { status: 400 });
  }
  const response = await fetch(`${API_BASE}/api/ai-actions/${encodeURIComponent(jobId)}`, {
    headers: await authHeaders(),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}

export async function DELETE(request: Request) {
  const jobId = new URL(request.url).searchParams.get("job");
  if (!jobId) {
    return NextResponse.json({ status: "Failed", message: "Missing AI action job id." }, { status: 400 });
  }
  const response = await fetch(`${API_BASE}/api/ai-actions/${encodeURIComponent(jobId)}`, {
    method: "DELETE",
    headers: await authHeaders(),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}
