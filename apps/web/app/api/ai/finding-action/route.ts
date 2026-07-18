import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { API_BASE } from "@/lib/api";
import { isE2EFixtureMode } from "@/lib/nope-data";

const actions = new Set(["explain", "challenge", "fix", "test", "regression_test", "patch_review"]);

async function authHeaders() {
  const token = (await cookies()).get("nope_session")?.value;
  const headers = new Headers();
  if (token) headers.set("authorization", `Bearer ${token}`);
  return headers;
}

function fixtureResult(action: string) {
  const labels: Record<string, { summary: string; reasoning: string; recommendation: string }> = {
    explain: {
      summary: "This finding means user-controlled input reaches sensitive behavior without enough proof of a guard.",
      reasoning: "NOPE uses the finding location, graph edge, scanner provenance, and nearby code context to explain why the issue matters without sending the whole repository to Qwen.",
      recommendation: "Inspect the referenced file and line range, then verify the missing guard with the regression test tab.",
    },
    challenge: {
      summary: "The challenge path asks whether the evidence is strong enough to keep the finding.",
      reasoning: "It looks for alternate guards, framework-level policy, false-positive signals, and missing context before recommending confirmation or dismissal.",
      recommendation: "Keep this finding confirmed in the fixture because the graph connects the route, file, database lookup, and risk edge.",
    },
    fix: {
      summary: "Patch the server-side boundary, not only the client route protection.",
      reasoning: "A durable fix should bind the resource query to the authenticated user or tenant and avoid trusting caller-provided ids alone.",
      recommendation: "Add an owner or tenant predicate, handle not-found as unauthorized-safe, and rerun the same folder scan.",
    },
    regression_test: {
      summary: "The regression test should prove the bypass does not come back.",
      reasoning: "Use two users, two resources, and a cross-user request so the test fails if the owner predicate is removed.",
      recommendation: "Add a negative authorization test and keep it tied to this finding fingerprint.",
    },
    patch_review: {
      summary: "Review the patch against the original evidence chain.",
      reasoning: "A patch is acceptable only if it breaks the risky route-to-data edge or adds a verified authorization edge.",
      recommendation: "Compare the changed files with the finding line range and require a passing regression test.",
    },
  };
  const copy = labels[action] ?? labels.explain;
  return {
    status: "Completed",
    state: "completed",
    message: "Fixture Qwen action completed.",
    job_id: `job_stage8_${action}`,
    model: "qwen3-8b-q4-k-m",
    cached: true,
    latency_ms: 250,
    context_chunks: 4,
    result: {
      summary: copy.summary,
      evidence: [
        "Finding fingerprint, scanner source, file, and line range were used.",
        "Graph context was bounded to the route, handler, data, and risk nodes.",
        "Repository instructions were treated as untrusted data.",
      ],
      reasoning: copy.reasoning,
      recommendation: copy.recommendation,
      confidence: "high",
      risk: "stage8-fixture",
    },
  };
}

export async function POST(request: Request) {
  const body = await request.json();
  const action = String(body.action ?? "");
  if (!actions.has(action)) {
    return NextResponse.json({ status: "Failed", message: "Unsupported finding AI action." }, { status: 400 });
  }
  if (isE2EFixtureMode()) {
    return NextResponse.json(fixtureResult(action));
  }

  const headers = await authHeaders();
  if (body.scanId && body.findingId) {
    const response = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(String(body.scanId))}/findings/${encodeURIComponent(String(body.findingId))}/ai-actions`, {
      method: "POST",
      headers: new Headers([["content-type", "application/json"], ...headers.entries()]),
      body: JSON.stringify({ action }),
      cache: "no-store",
    });
    const result = await response.json();
    return NextResponse.json(result, { status: response.status });
  }

  const response = await fetch(`${API_BASE}/api/findings/${action}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...Object.fromEntries(headers.entries()),
    },
    body: JSON.stringify(body.finding),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}

export async function GET(request: Request) {
  const jobId = new URL(request.url).searchParams.get("job");
  if (!jobId) {
    return NextResponse.json({ status: "Failed", message: "Missing AI action job id." }, { status: 400 });
  }
  if (isE2EFixtureMode()) {
    const action = jobId.replace("job_stage8_", "") || "explain";
    return NextResponse.json(fixtureResult(action));
  }
  const response = await fetch(`${API_BASE}/api/ai-actions/${encodeURIComponent(jobId)}`, {
    headers: await authHeaders(),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}

export async function DELETE(request: Request) {
  const jobId = new URL(request.url).searchParams.get("job");
  if (!jobId) {
    return NextResponse.json({ status: "Failed", message: "Missing AI action job id." }, { status: 400 });
  }
  if (isE2EFixtureMode()) {
    return NextResponse.json({ status: "Cancelled", state: "cancelled", message: "Fixture Qwen action cancelled." });
  }
  const response = await fetch(`${API_BASE}/api/ai-actions/${encodeURIComponent(jobId)}`, {
    method: "DELETE",
    headers: await authHeaders(),
    cache: "no-store",
  });
  const result = await response.json();
  return NextResponse.json(result, { status: response.status });
}
