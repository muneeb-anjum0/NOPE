import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";

export async function POST(request: Request) {
  const form = await request.formData();
  const scanId = String(form.get("scanId") ?? "");
  if (!scanId) {
    return NextResponse.redirect(new URL("/app/projects/local/scans?error=Choose a scan to delete.", request.url), 303);
  }

  const headers = new Headers();
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}`, {
    method: "DELETE",
    headers,
  });

  const next = new URL("/app/projects/local/scans", request.url);
  if (!response.ok) {
    const detail = await response.text();
    next.searchParams.set("error", detail || `Delete failed with ${response.status}.`);
  }
  return NextResponse.redirect(next, 303);
}
