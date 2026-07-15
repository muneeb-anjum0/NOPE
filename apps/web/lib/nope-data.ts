import { api } from "@/lib/api";
import type { AIHealth, FindingDetail, FindingsResult, ModelSettings, Scan } from "@/lib/types";

export async function getScans(): Promise<Scan[]> {
  try {
    return await api<Scan[]>("/api/scans");
  } catch {
    return [];
  }
}

export async function getLatestScan(): Promise<Scan | null> {
  const scans = await getScans();
  return scans[0] ?? null;
}

export async function getFindings(scanId: string, searchParams?: URLSearchParams): Promise<FindingsResult | null> {
  try {
    const query = searchParams?.toString();
    return await api<FindingsResult>(`/api/scans/${scanId}/findings${query ? `?${query}` : ""}`);
  } catch {
    return null;
  }
}

export async function getFindingDetail(scanId: string, findingId: string): Promise<FindingDetail | null> {
  try {
    return await api<FindingDetail>(`/api/scans/${scanId}/findings/${findingId}`);
  } catch {
    return null;
  }
}

export async function getModelSettings(): Promise<ModelSettings | null> {
  try {
    return await api<ModelSettings>("/api/settings/model");
  } catch {
    return null;
  }
}

export async function getAIHealth(): Promise<AIHealth | null> {
  try {
    const health = await api<{ ai: { health: AIHealth } }>("/health");
    return health.ai.health;
  } catch {
    return null;
  }
}

export function freshScan(): Scan {
  return {
    id: "fresh_workspace",
    status: "ready",
    mode: "full",
    verdict: "Fresh dashboard. Run a scan when ready.",
    score: 0,
    coverage_percent: 0,
    repository_name: "not connected",
    target_url: null,
    branch: null,
    commit_sha: null,
    findings: [],
    coverage: [
      { domain: "Secrets", status: "Not tested", scanners: [], notes: "Run a repository scan to check for leaked credentials." },
      { domain: "Authentication", status: "Not tested", scanners: [], notes: "Run a full scan to inspect session and login surfaces." },
      { domain: "Authorization", status: "Not tested", scanners: [], notes: "Run a full scan to inspect server-side access checks." },
      { domain: "Dependencies", status: "Not tested", scanners: [], notes: "Dependency scanners have not run for this workspace yet." },
      { domain: "Dynamic testing", status: "Not tested", scanners: [], notes: "No authorized runtime target has been tested yet." },
    ],
    scanner_runs: [],
    code_graph: { nodes: [] },
    ai_review: { status: "Not tested", provider: "none", message: "Run a scan to generate focused evidence for Qwen review." },
  };
}

export function demoScan(): Scan {
  return {
    id: "scan_demo_local",
    status: "demo",
    mode: "repository",
    verdict: "Maybe. Coverage is incomplete.",
    score: 64,
    coverage_percent: 47,
    repository_name: "local demo",
    target_url: "https://example.local",
    branch: "main",
    commit_sha: "local",
    findings: [
      {
        id: "demo_1",
        severity: "critical",
        title: "Client-provided role trusted",
        category: "Authorization",
        affected_file: "app/api/invoices/[id]/route.ts",
        confidence: "medium",
        scanner_sources: ["NOPE rules"],
        status: "open",
        remediation: "Derive roles from the authenticated server-side session and test tampering.",
      },
      {
        id: "demo_2",
        severity: "high",
        title: "Database lookup by ID may lack owner scope",
        category: "IDOR",
        affected_file: "app/api/invoices/[id]/route.ts",
        confidence: "medium",
        scanner_sources: ["NOPE rules"],
        status: "open",
        remediation: "Constrain resource queries by authenticated user, tenant, or explicit policy.",
      },
      {
        id: "demo_3",
        severity: "medium",
        title: "AI call may lack cost controls",
        category: "AI abuse",
        affected_file: "app/api/ai/route.ts",
        confidence: "medium",
        scanner_sources: ["NOPE rules"],
        status: "open",
        remediation: "Add token caps, timeouts, budgets, and per-user throttles.",
      },
    ],
    coverage: [
      { domain: "Authorization", status: "Verified", scanners: ["NOPE rules"], notes: "Static rule coverage." },
      { domain: "Secrets", status: "Verified", scanners: ["NOPE rules"], notes: "Secret patterns checked." },
      { domain: "Dependencies", status: "Failed", scanners: ["Trivy"], notes: "External scanner unavailable." },
      { domain: "Dynamic testing", status: "Not tested", scanners: [], notes: "No sandbox run was executed." },
      { domain: "Qwen AI review", status: "Not tested", scanners: [], notes: "AI runtime not configured." },
    ],
    scanner_runs: [
      { scanner: "NOPE rules", status: "passed", message: "", findings_count: 3, coverage_categories: ["Authorization", "Secrets"] },
      { scanner: "Trivy", status: "failed", message: "trivy was not found on PATH.", findings_count: 0, coverage_categories: ["Dependencies"] },
    ],
    code_graph: {
      nodes: [
        { id: "route", label: "ANY /api/invoices/:id", kind: "entry point" },
        { id: "file", label: "route.ts", kind: "file" },
        { id: "db", label: "prisma.invoice.findUnique", kind: "database", risk: "high" },
      ],
    },
    ai_review: { status: "Not tested", provider: "none", message: "AI provider is disabled." },
  };
}

export function severityClass(severity: string) {
  return `severity-pill severity-${severity}`;
}
