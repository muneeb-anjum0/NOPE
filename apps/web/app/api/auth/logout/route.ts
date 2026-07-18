import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";
import { isE2EFixtureMode } from "@/lib/nope-data";

export async function POST(request: Request) {
  const cookieStore = await cookies();
  const token = cookieStore.get("nope_session")?.value;
  if (isE2EFixtureMode()) {
    cookieStore.delete("nope_session");
    return NextResponse.redirect(new URL("/", request.url), 303);
  }
  if (token) {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
    }).catch(() => undefined);
  }
  cookieStore.delete("nope_session");
  return NextResponse.redirect(new URL("/", request.url), 303);
}
