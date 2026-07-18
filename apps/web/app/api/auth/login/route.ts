import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";
import { isE2EFixtureMode } from "@/lib/nope-data";

export async function POST(request: Request) {
  const form = await request.formData();
  const email = String(form.get("email") ?? "");
  const password = String(form.get("password") ?? "");
  if (isE2EFixtureMode()) {
    (await cookies()).set("nope_session", "stage8-e2e-session", {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    });
    return NextResponse.redirect(new URL("/app/projects/local", request.url), 303);
  }
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({ detail: "Login failed." }));
    return NextResponse.redirect(new URL(`/login?error=${encodeURIComponent(data.detail ?? "Login failed.")}`, request.url), 303);
  }
  const data = (await response.json()) as { token: string };
  (await cookies()).set("nope_session", data.token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  });
  return NextResponse.redirect(new URL("/app/projects/local", request.url), 303);
}
