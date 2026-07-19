import { api } from "@/lib/api";
import type {
  AIHealth,
  FindingDetail,
  FindingsResult,
  GitHubStatus,
  ModelSettings,
  Project,
  ProjectSettings,
  RulesV2CandidateResult,
  RulesV2Summary,
  Scan,
  ScanComparison,
  SecurityBaseline,
  SystemSettings,
} from "@/lib/types";
import {
  e2eAIHealth,
  e2eBaselines,
  e2eComparison,
  e2eFindingDetail,
  e2eFindings,
  e2eGitHubStatus,
  e2eModelSettings,
  e2eProjects,
  e2eProjectSettings,
  e2eScans,
  e2eSystemSettings,
} from "@/lib/e2e-fixtures";

export function isE2EFixtureMode() {
  return process.env.NOPE_E2E_FIXTURE === "1";
}

export async function getScans(): Promise<Scan[]> {
  if (isE2EFixtureMode()) return e2eScans;
  try {
    return await api<Scan[]>("/api/scans");
  } catch {
    return [];
  }
}

export async function getScan(scanId: string): Promise<Scan | null> {
  if (isE2EFixtureMode()) return e2eScans.find((scan) => scan.id === scanId) ?? null;
  try {
    return await api<Scan>(`/api/scans/${encodeURIComponent(scanId)}`);
  } catch {
    return null;
  }
}

export function selectScan(scans: Scan[], scanId?: string | null): Scan | null {
  if (!scans.length) return null;
  if (!scanId) return scans[0] ?? null;
  return scans.find((scan) => scan.id === scanId) ?? scans[0] ?? null;
}

export async function getProjects(): Promise<Project[]> {
  if (isE2EFixtureMode()) return e2eProjects;
  try {
    return await api<Project[]>("/api/projects");
  } catch {
    return [];
  }
}

export async function getLatestScan(): Promise<Scan | null> {
  const scans = await getScans();
  return scans[0] ?? null;
}

export async function getFindings(scanId: string, searchParams?: URLSearchParams): Promise<FindingsResult | null> {
  if (isE2EFixtureMode()) return e2eFindings(scanId, searchParams);
  try {
    const query = searchParams?.toString();
    return await api<FindingsResult>(`/api/scans/${scanId}/findings${query ? `?${query}` : ""}`);
  } catch {
    return null;
  }
}

export async function getFindingDetail(scanId: string, findingId: string): Promise<FindingDetail | null> {
  if (isE2EFixtureMode()) return e2eFindingDetail(scanId, findingId);
  try {
    return await api<FindingDetail>(`/api/scans/${scanId}/findings/${findingId}`);
  } catch {
    return null;
  }
}

export async function getRulesV2Summary(scanId: string): Promise<RulesV2Summary | null> {
  if (isE2EFixtureMode()) {
    const scan = e2eScans.find((item) => item.id === scanId);
    return {
      scan_id: scanId,
      version: "rules-v2.fixture",
      catalog: { rule_count: 101 },
      coverage: {
        candidate_count: 9,
        promoted: scan?.findings?.length ?? 0,
        withheld: 3,
        rejected: 2,
        needs_manual_review: 1,
        not_applicable: 0,
        by_family: { correlation: { promoted: 2, withheld: 1 }, nextjs: { rejected: 1 }, prisma: { withheld: 2 } },
      },
      metrics: { total_ms: 31, repository_files_considered: 79 },
      failures: [],
    };
  }
  try {
    return await api<RulesV2Summary>(`/api/scans/${scanId}/rules-v2`);
  } catch {
    return null;
  }
}

export async function getRulesV2Candidates(scanId: string, searchParams?: URLSearchParams): Promise<RulesV2CandidateResult | null> {
  if (isE2EFixtureMode()) {
    return {
      scan_id: scanId,
      page: 1,
      page_size: 25,
      total: 3,
      items: [
        {
          candidate: {
            candidate_id: "rv2_fixture_promoted",
            rule_id: "NOPE-CORR-IDOR-001",
            family: "correlation",
            preliminary_severity: "high",
            preliminary_confidence: "high",
            file: "Raqm/apps/web/src/routes/app/invoices/[id]/+server.ts",
            line: 42,
            source_type: "attack_surface",
            evidence: [{ source: "Rules v2", message: "Route parameter reaches a database lookup with no owner predicate.", strength: "strong_correlated" }],
          },
          decision: { candidate_id: "rv2_fixture_promoted", rule_id: "NOPE-CORR-IDOR-001", result: "promoted", confidence: "high", evidence_strength: "strong_correlated", reason: "Required evidence was present and no safe pattern contradicted it." },
        },
        {
          candidate: {
            candidate_id: "rv2_fixture_withheld",
            rule_id: "NOPE-PRISMA-001",
            family: "prisma",
            preliminary_severity: "high",
            preliminary_confidence: "medium",
            file: "Raqm/apps/web/src/routes/app/profile/+server.ts",
            line: 17,
            missing_evidence: ["owner/tenant predicate"],
          },
          decision: { candidate_id: "rv2_fixture_withheld", rule_id: "NOPE-PRISMA-001", result: "withheld", confidence: "medium", evidence_strength: "incomplete", reason: "Suspicious, but missing evidence keeps it out of confirmed findings." },
        },
        {
          candidate: {
            candidate_id: "rv2_fixture_rejected",
            rule_id: "NOPE-NEXT-AUTHZ-004",
            family: "nextjs",
            preliminary_severity: "high",
            preliminary_confidence: "low",
            file: "Raqm/apps/web/src/routes/app/settings/+server.ts",
            line: 61,
            safe_pattern_evidence: ["owner predicate present"],
          },
          decision: { candidate_id: "rv2_fixture_rejected", rule_id: "NOPE-NEXT-AUTHZ-004", result: "rejected", confidence: "low", evidence_strength: "contradictory", reason: "A safe-pattern contradiction prevented promotion." },
        },
      ],
    };
  }
  try {
    const query = searchParams?.toString();
    return await api<RulesV2CandidateResult>(`/api/scans/${scanId}/rules-v2/candidates${query ? `?${query}` : ""}`);
  } catch {
    return null;
  }
}

export async function getBaselines(projectId?: string | null): Promise<SecurityBaseline[]> {
  if (isE2EFixtureMode()) return projectId ? e2eBaselines.filter((baseline) => baseline.project_id === projectId) : e2eBaselines;
  try {
    const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
    return await api<SecurityBaseline[]>(`/api/baselines${query}`);
  } catch {
    return [];
  }
}

export async function getScanComparison(scanId: string, againstScanId?: string): Promise<ScanComparison | null> {
  if (isE2EFixtureMode()) return { ...e2eComparison, current_scan_id: scanId, reference_scan_id: againstScanId ?? e2eComparison.reference_scan_id };
  try {
    const query = againstScanId ? `?against_scan_id=${encodeURIComponent(againstScanId)}` : "";
    return await api<ScanComparison>(`/api/scans/${scanId}/compare${query}`);
  } catch {
    return null;
  }
}

export async function getModelSettings(): Promise<ModelSettings | null> {
  if (isE2EFixtureMode()) return e2eModelSettings;
  try {
    return await api<ModelSettings>("/api/settings/model");
  } catch {
    return null;
  }
}

export async function getSystemSettings(): Promise<SystemSettings | null> {
  if (isE2EFixtureMode()) return e2eSystemSettings;
  try {
    return await api<SystemSettings>("/api/settings/system");
  } catch {
    return null;
  }
}

export async function getProjectSettings(projectId: string): Promise<ProjectSettings | null> {
  if (isE2EFixtureMode()) return { ...e2eProjectSettings, project_id: projectId };
  try {
    return await api<ProjectSettings>(`/api/projects/${projectId}/settings`);
  } catch {
    return null;
  }
}

export async function getGitHubStatus(): Promise<GitHubStatus | null> {
  if (isE2EFixtureMode()) return e2eGitHubStatus;
  try {
    return await api<GitHubStatus>("/api/github/status");
  } catch {
    return null;
  }
}

export async function getAIHealth(): Promise<AIHealth | null> {
  if (isE2EFixtureMode()) return e2eAIHealth;
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
    code_graph: { nodes: [], edges: [] },
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
      edges: [
        { source: "route", target: "file", relationship: "handled by" },
        { source: "file", target: "db", relationship: "retrieves data from" },
      ],
    },
    ai_review: { status: "Not tested", provider: "none", message: "AI provider is disabled." },
  };
}

export function severityClass(severity: string) {
  return `severity-pill severity-${severity}`;
}
