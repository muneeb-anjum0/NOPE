import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";
import { E2E_SCAN_RUNNING, e2eScans } from "@/lib/e2e-fixtures";
import { isE2EFixtureMode } from "@/lib/nope-data";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(request: Request, { params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  if (isE2EFixtureMode()) {
    const scan = e2eScans.find((item) => item.id === scanId);
    const running = scanId === E2E_SCAN_RUNNING;
    return NextResponse.json({
      scan_id: scanId,
      status: running ? "running" : (scan?.status ?? "completed"),
      progress: running ? 57 : 100,
      stages: [
        { name: "Upload", status: "completed" },
        { name: "Stack", status: "completed" },
        { name: "Scanners", status: running ? "running" : "completed" },
        { name: "Qwen", status: running ? "queued" : "completed" },
      ],
      events: [
        { sequence: 1, type: "scan_created", status: "queued" },
        { sequence: 2, type: "worker_heartbeat", status: "running" },
      ],
    }, { headers: { "cache-control": "no-store, max-age=0" } });
  }
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
