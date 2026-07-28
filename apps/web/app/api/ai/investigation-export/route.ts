import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { API_BASE } from "@/lib/api";

async function authHeaders() {
  const token = (await cookies()).get("nope_session")?.value;
  const headers = new Headers();
  if (token) headers.set("authorization", `Bearer ${token}`);
  return headers;
}

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const job = params.get("job");
  const format = params.get("format") ?? "md";
  if (!job) {
    return NextResponse.json({ status: "Failed", message: "Missing investigation job id." }, { status: 400 });
  }
  if (!["json", "md", "markdown", "pdf"].includes(format)) {
    return NextResponse.json({ status: "Failed", message: "Unsupported investigation export format." }, { status: 400 });
  }
  const response = await fetch(`${API_BASE}/api/ai-actions/${encodeURIComponent(job)}/investigation.${encodeURIComponent(format)}`, {
    headers: await authHeaders(),
    cache: "no-store",
  });
  const body = await response.arrayBuffer();
  return new Response(body, {
    status: response.status,
    headers: {
      "content-type": response.headers.get("content-type") ?? "application/octet-stream",
      "content-disposition": response.headers.get("content-disposition") ?? `attachment; filename="nope-investigation.${format}"`,
    },
  });
}
