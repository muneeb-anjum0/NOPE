import { NextResponse } from "next/server";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("repository");
  const targetUrl = String(form.get("targetUrl") ?? "");
  const confirmed = form.get("confirmed") === "on";

  if (file instanceof File && file.size > 0 && targetUrl) {
    const full = new FormData();
    full.append("file", file);
    full.append("target_url", targetUrl);
    full.append("authorization_confirmed", String(confirmed));
    const host = new URL(targetUrl).hostname;
    full.append("approved_hosts", host);
    await fetch(`${API_BASE}/api/scans/full`, { method: "POST", body: full });
  } else if (file instanceof File && file.size > 0) {
    const repo = new FormData();
    repo.append("file", file);
    await fetch(`${API_BASE}/api/scans/repository`, { method: "POST", body: repo });
  } else if (targetUrl) {
    await fetch(`${API_BASE}/api/scans/url`, {
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

  return NextResponse.redirect(new URL("/", request.url));
}
