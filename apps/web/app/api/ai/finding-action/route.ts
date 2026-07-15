import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { API_BASE } from "@/lib/api";

const actions = new Set(["explain", "challenge", "fix", "test"]);

export async function POST(request: Request) {
  const body = await request.json();
  const action = String(body.action ?? "");
  if (!actions.has(action)) {
    return NextResponse.json({ status: "Failed", message: "Unsupported finding AI action." }, { status: 400 });
  }

  const token = (await cookies()).get("nope_session")?.value;
  const response = await fetch(`${API_BASE}/api/findings/${action}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body.finding),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}
