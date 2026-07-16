import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(_request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const headers = new Headers();
  const token = (await cookies()).get("nope_session")?.value;
  if (token) headers.set("authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/events`, {
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
