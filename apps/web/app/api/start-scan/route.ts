import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { API_BASE } from "@/lib/api";

function redirectWithError(request: Request, message: string) {
  return NextResponse.redirect(new URL(`/app/projects/local/scans?error=${encodeURIComponent(message)}`, request.url), 303);
}

async function forwardScan(request: Request, path: string, init: RequestInit) {
  const headers = new Headers(init.headers);
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!response.ok) {
    const detail = await response.text();
    return redirectWithError(request, detail || `Scan request failed with ${response.status}.`);
  }
  const payload = (await response.json().catch(() => null)) as { id?: string } | null;
  const next = new URL("/app/projects/local/scans", request.url);
  if (payload?.id) next.searchParams.set("scan", payload.id);
  return NextResponse.redirect(next, 303);
}

export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("repository");
  const targetUrl = String(form.get("targetUrl") ?? "");
  const repositoryName =
    String(form.get("repositoryName") ?? "") ||
    (file instanceof File && file.name ? file.name : "") ||
    "Uploaded ZIP";
  const confirmed = form.get("confirmed") === "on";

  if (file instanceof File && file.size > 0 && targetUrl) {
    const full = new FormData();
    full.append("file", file);
    full.append("target_url", targetUrl);
    full.append("repository_name", repositoryName);
    full.append("authorization_confirmed", String(confirmed));
    const host = new URL(targetUrl).hostname;
    full.append("approved_hosts", host);
    return forwardScan(request, "/api/scans/full", { method: "POST", body: full });
  } else if (file instanceof File && file.size > 0) {
    const repo = new FormData();
    repo.append("file", file);
    repo.append("repository_name", repositoryName);
    return forwardScan(request, "/api/scans/repository", { method: "POST", body: repo });
  } else if (targetUrl) {
    return forwardScan(request, "/api/scans/url", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        mode: "url",
        target_url: targetUrl,
        authorization: {
          confirmed,
          confirmed_at: confirmed ? new Date().toISOString() : null,
          approved_hosts: [new URL(targetUrl).hostname],
        },
      }),
    });
  }

  return redirectWithError(request, "Choose a repository ZIP, enter a target URL, or provide both.");
}
