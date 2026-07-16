import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { ACTIVE_PROJECT_COOKIE } from "@/lib/active-project";

const API_BASE = process.env.API_URL_INTERNAL || "http://localhost:8000";

export async function POST(request: Request) {
  const form = await request.formData();
  const projectId = String(form.get("projectId") ?? "");
  const next = new URL("/app/projects/local/scans", request.url);
  if (!projectId) {
    next.searchParams.set("error", "Choose a project folder to delete.");
    return NextResponse.redirect(next, 303);
  }

  const token = (await cookies()).get("nope_session")?.value;
  const response = await fetch(`${API_BASE}/api/projects/${encodeURIComponent(projectId)}`, {
    method: "DELETE",
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    next.searchParams.set("error", detail || `Project delete failed with ${response.status}.`);
    return NextResponse.redirect(next, 303);
  }

  const jar = await cookies();
  if (jar.get(ACTIVE_PROJECT_COOKIE)?.value === projectId) {
    jar.delete(ACTIVE_PROJECT_COOKIE);
  }
  return NextResponse.redirect(next, 303);
}
