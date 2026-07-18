import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";
import { ACTIVE_PROJECT_COOKIE } from "@/lib/active-project";
import { E2E_PROJECT_ID } from "@/lib/e2e-fixtures";
import { isE2EFixtureMode } from "@/lib/nope-data";

function detailMessage(detail: string, fallback: string) {
  try {
    const parsed = JSON.parse(detail) as { detail?: unknown };
    return typeof parsed.detail === "string" ? parsed.detail : fallback;
  } catch {
    return detail || fallback;
  }
}

export async function POST(request: Request) {
  const form = await request.formData();
  const name = String(form.get("name") ?? "").trim();
  const repository = String(form.get("repository") ?? "").trim();
  const targetUrl = String(form.get("targetUrl") ?? "").trim();
  const next = new URL("/app/projects/local/scans", request.url);

  if (!name) {
    next.searchParams.set("error", "Name the folder first.");
    return NextResponse.redirect(next, 303);
  }

  if (isE2EFixtureMode()) {
    (await cookies()).set(ACTIVE_PROJECT_COOKIE, E2E_PROJECT_ID, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
    return NextResponse.redirect(next, 303);
  }

  const headers = new Headers({ "content-type": "application/json" });
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}/api/projects`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      name,
      repository: repository || null,
      target_url: targetUrl || null,
    }),
  });

  if (!response.ok) {
    const detail = await response.text();
    next.searchParams.set("error", detailMessage(detail, `Folder creation failed with ${response.status}.`));
    return NextResponse.redirect(next, 303);
  }

  const project = (await response.json().catch(() => null)) as { id?: string } | null;
  if (project?.id) {
    (await cookies()).set(ACTIVE_PROJECT_COOKIE, project.id, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
  }
  return NextResponse.redirect(next, 303);
}
