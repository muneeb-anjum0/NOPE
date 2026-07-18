import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";
import { isE2EFixtureMode } from "@/lib/nope-data";

function nextUrl(request: Request, projectId: string, scanId: string) {
  const next = new URL(projectId ? `/app/projects/local/scans/${encodeURIComponent(projectId)}` : "/app/projects/local/scans", request.url);
  if (scanId) next.searchParams.set("scan", scanId);
  return next;
}

export async function POST(request: Request) {
  const form = await request.formData();
  const scanId = String(form.get("scanId") ?? "");
  const projectId = String(form.get("projectId") ?? "");
  const action = String(form.get("action") ?? "");
  const next = nextUrl(request, projectId, scanId);
  if (!scanId || !["cancel", "retry"].includes(action)) {
    next.searchParams.set("error", "Choose a valid scan action.");
    return NextResponse.redirect(next, 303);
  }
  if (isE2EFixtureMode()) {
    next.searchParams.set("action", action);
    return NextResponse.redirect(next, 303);
  }
  const headers = new Headers();
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/${action}`, {
    method: "POST",
    headers,
  });
  if (!response.ok) {
    const detail = await response.text();
    next.searchParams.set("error", detail || `${action} failed with ${response.status}.`);
  }
  return NextResponse.redirect(next, 303);
}
