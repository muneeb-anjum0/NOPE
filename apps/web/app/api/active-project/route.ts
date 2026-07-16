import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { ACTIVE_PROJECT_COOKIE } from "@/lib/active-project";

function safeReturnTo(value: FormDataEntryValue | string | null) {
  const path = String(value || "/app/projects/local");
  return path.startsWith("/app") ? path : "/app/projects/local";
}

async function setActiveProject(projectId: string) {
  const jar = await cookies();
  if (projectId) {
    jar.set(ACTIVE_PROJECT_COOKIE, projectId, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
  } else {
    jar.delete(ACTIVE_PROJECT_COOKIE);
  }
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  await setActiveProject(url.searchParams.get("projectId") ?? "");
  return NextResponse.redirect(new URL(safeReturnTo(url.searchParams.get("returnTo")), request.url), 303);
}

export async function POST(request: Request) {
  const form = await request.formData();
  await setActiveProject(String(form.get("projectId") ?? ""));
  return NextResponse.redirect(new URL(safeReturnTo(form.get("returnTo")), request.url), 303);
}
