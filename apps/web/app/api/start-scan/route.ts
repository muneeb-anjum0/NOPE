import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { API_BASE } from "@/lib/api";
import { E2E_SCAN_RUNNING } from "@/lib/e2e-fixtures";
import { isE2EFixtureMode } from "@/lib/nope-data";

function redirectWithError(request: Request, message: string, projectId?: string, scaffoldWarning = false) {
  const next = new URL(projectId ? `/app/projects/local/scans/${encodeURIComponent(projectId)}` : "/app/projects/local/scans", request.url);
  next.searchParams.set(scaffoldWarning ? "scaffoldWarning" : "error", message);
  return NextResponse.redirect(next, 303);
}

function detailMessage(detail: string, fallback: string) {
  try {
    const parsed = JSON.parse(detail) as { detail?: unknown };
    return typeof parsed.detail === "string" ? parsed.detail : fallback;
  } catch {
    return detail || fallback;
  }
}

async function forwardScan(request: Request, path: string, init: RequestInit, projectId?: string) {
  const headers = new Headers(init.headers);
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!response.ok) {
    const detail = await response.text();
    return redirectWithError(
      request,
      detailMessage(detail, `Scan request failed with ${response.status}.`),
      projectId,
      response.status === 409,
    );
  }
  const payload = (await response.json().catch(() => null)) as { id?: string } | null;
  const next = new URL(projectId ? `/app/projects/local/scans/${encodeURIComponent(projectId)}` : "/app/projects/local/scans", request.url);
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
  const projectId = String(form.get("projectId") ?? "");
  const forceScaffold = form.get("forceScaffold") === "on";

  if (isE2EFixtureMode()) {
    const next = new URL(projectId ? `/app/projects/local/scans/${encodeURIComponent(projectId)}` : "/app/projects/local/scans", request.url);
    next.searchParams.set("scan", E2E_SCAN_RUNNING);
    return NextResponse.redirect(next, 303);
  }

  if (file instanceof File && file.size > 0 && targetUrl) {
    const full = new FormData();
    full.append("file", file);
    full.append("target_url", targetUrl);
    full.append("repository_name", repositoryName);
    full.append("authorization_confirmed", String(confirmed));
    if (projectId) full.append("project_id", projectId);
    full.append("force_scaffold", String(forceScaffold));
    const host = new URL(targetUrl).hostname;
    full.append("approved_hosts", host);
    return forwardScan(request, "/api/scans/full", { method: "POST", body: full }, projectId);
  } else if (file instanceof File && file.size > 0) {
    const repo = new FormData();
    repo.append("file", file);
    repo.append("repository_name", repositoryName);
    if (projectId) repo.append("project_id", projectId);
    repo.append("force_scaffold", String(forceScaffold));
    return forwardScan(request, "/api/scans/repository", { method: "POST", body: repo }, projectId);
  } else if (targetUrl) {
    return forwardScan(request, "/api/scans/url", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        project_id: projectId || null,
        mode: "url",
        target_url: targetUrl,
        authorization: {
          confirmed,
          confirmed_at: confirmed ? new Date().toISOString() : null,
          approved_hosts: [new URL(targetUrl).hostname],
        },
      }),
    }, projectId);
  }

  return redirectWithError(request, "Choose a repository ZIP, enter a target URL, or provide both.", projectId);
}
