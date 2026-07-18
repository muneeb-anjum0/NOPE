import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const incoming = new URL(request.url);
  const query = new URLSearchParams();
  for (const key of ["after_sequence", "limit"]) {
    const value = incoming.searchParams.get(key);
    if (value) query.set(key, value);
  }
  const headers = new Headers();
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);

  const suffix = query.size ? `?${query.toString()}` : "";
  const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/events${suffix}`, {
    headers,
    cache: "no-store",
  });
  const body = await response.text();
  return new NextResponse(body, {
    status: response.status,
    headers: {
      "cache-control": "no-store, max-age=0",
      "content-type": response.headers.get("content-type") ?? "application/json",
    },
  });
}
