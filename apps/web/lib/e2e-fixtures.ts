import type { AIHealth, FindingDetail, FindingsResult, GitHubStatus, ModelSettings, Project, ProjectSettings, Scan, ScanComparison, SecurityBaseline, SystemSettings } from "@/lib/types";

export const E2E_PROJECT_ID = "project_stage8";
export const E2E_SCAN_COMPLETED = "scan_stage8_completed";
export const E2E_SCAN_RUNNING = "scan_stage8_running";
export const E2E_SCAN_PARTIAL = "scan_stage8_partial";
export const E2E_SCAN_FAILED = "scan_stage8_failed";

const now = "2026-07-18T10:30:00.000Z";

const findings = [
  {
    id: "fnd_stage8_secret",
    fingerprint: "fp-stage8-secret",
    severity: "high" as const,
    title: "Potential hardcoded secret",
    description: "A secret-like assignment is present in server-side code and should be rotated or moved into managed configuration.",
    category: "Secrets",
    affected_file: "Raqm/apps/web/src/lib/crypto-vault.js",
    start_line: 105,
    end_line: 108,
    confidence: "high",
    scanner_sources: ["NOPE rules", "Gitleaks"],
    status: "new",
    nope_rule_id: "NOPE-SECRETS-001",
    remediation: "Move the value into a secret manager, rotate the exposed credential, and add a regression check that prevents checked-in secret-like assignments.",
    test_guidance: "Add a fixture with a known fake token and assert the scanner reports it while ignoring documented allowlisted examples.",
    evidence: [
      { source: "NOPE rules", file: "Raqm/apps/web/src/lib/crypto-vault.js", line: 105, snippet: "const serviceToken = \"stage8-demo-token\";", message: "Secret-like assignment matched a high-confidence rule." },
    ],
  },
  {
    id: "fnd_stage8_idor",
    fingerprint: "fp-stage8-idor",
    severity: "critical" as const,
    title: "Invoice lookup may lack owner scope",
    description: "The route receives a caller-controlled invoice id and reaches a database lookup without a mapped owner or tenant predicate.",
    category: "Authorization",
    affected_file: "Raqm/apps/web/src/routes/app/invoices/[id]/+server.ts",
    affected_route: "GET /app/invoices/:id",
    start_line: 43,
    end_line: 51,
    confidence: "confirmed",
    scanner_sources: ["NOPE rules", "Graph validator", "Qwen challenge"],
    status: "confirmed",
    nope_rule_id: "NOPE-AUTHZ-001",
    remediation: "Constrain the invoice query by the authenticated user's tenant id and add a cross-user regression test.",
    test_guidance: "Seed two users and assert user A cannot retrieve user B's invoice id.",
    evidence: [
      { source: "Graph validator", file: "Raqm/apps/web/src/routes/app/invoices/[id]/+server.ts", line: 48, snippet: "db.invoice.findUnique({ where: { id } })", message: "Route id flows to a database lookup without an ownership edge." },
    ],
  },
  {
    id: "fnd_stage8_dynamic",
    fingerprint: "fp-stage8-dynamic",
    severity: "medium" as const,
    title: "Missing security headers on dashboard route",
    description: "The dynamic scan observed a page response without a content security policy.",
    category: "Dynamic testing",
    affected_route: "GET /app",
    start_line: null,
    end_line: null,
    confidence: "medium",
    scanner_sources: ["ZAP baseline"],
    status: "fixing",
    nope_rule_id: "ZAP-10038",
    remediation: "Add a restrictive Content-Security-Policy header and verify it during the dynamic scan.",
    test_guidance: "Use a browser response assertion for the CSP header and rerun ZAP baseline.",
    evidence: [
      { source: "ZAP baseline", file: null, line: null, snippet: null, message: "CSP header was absent on the authenticated dashboard response." },
    ],
  },
  {
    id: "fnd_stage8_dependency",
    fingerprint: "fp-stage8-dependency",
    severity: "medium" as const,
    title: "uuid: CVE-2026-41907",
    description: "A dependency advisory affects the installed package version.",
    category: "Dependencies",
    affected_file: "Raqm/apps/web/package-lock.json",
    start_line: 512,
    end_line: 540,
    confidence: "high",
    scanner_sources: ["npm audit", "OSV-Scanner"],
    status: "new",
    cve: "CVE-2026-41907",
    remediation: "Upgrade uuid to the fixed version reported by the package audit and rerun dependency scanners.",
    test_guidance: "Assert the lockfile no longer resolves the vulnerable package version.",
    evidence: [
      { source: "npm audit", file: "Raqm/apps/web/package-lock.json", line: 512, snippet: "\"uuid\": \"8.0.0\"", message: "Audit advisory maps to the package lock entry." },
    ],
  },
  {
    id: "fnd_stage8_storage",
    fingerprint: "fp-stage8-storage",
    severity: "low" as const,
    title: "Public storage bucket policy should be reviewed",
    description: "A storage policy grants public reads and needs an explicit business justification.",
    category: "Storage",
    affected_file: "Raqm/supabase/policies.sql",
    start_line: 76,
    end_line: 82,
    confidence: "medium",
    scanner_sources: ["Supabase rules"],
    status: "accepted_risk",
    nope_rule_id: "NOPE-SUPABASE-006",
    remediation: "Document the public-read scope or change the policy to authenticated reads only.",
    test_guidance: "Use an unauthenticated storage request to prove private buckets reject reads.",
    evidence: [
      { source: "Supabase rules", file: "Raqm/supabase/policies.sql", line: 76, snippet: "using (bucket_id = 'public-assets')", message: "Public bucket policy detected." },
    ],
  },
  {
    id: "fnd_stage8_ci",
    fingerprint: "fp-stage8-ci",
    severity: "info" as const,
    title: "No HEALTHCHECK defined",
    description: "The web Dockerfile has no runtime healthcheck, so orchestration may miss a broken process.",
    category: "CI/CD",
    affected_file: "Raqm/docker/web.Dockerfile",
    start_line: 1,
    end_line: 42,
    confidence: "medium",
    scanner_sources: ["Hadolint"],
    status: "verified",
    remediation: "Add a low-cost health endpoint check to the production container.",
    test_guidance: "Build the image and assert Docker reports a healthy container.",
    evidence: [
      { source: "Hadolint", file: "Raqm/docker/web.Dockerfile", line: 1, snippet: "FROM node:22-alpine", message: "Dockerfile does not define HEALTHCHECK." },
    ],
  },
  {
    id: "fnd_stage8_rate",
    fingerprint: "fp-stage8-rate",
    severity: "low" as const,
    title: "AI endpoint lacks per-user token budget",
    description: "A route can reach the local model without a mapped per-user daily budget.",
    category: "AI cost abuse",
    affected_file: "Raqm/apps/web/src/routes/api/ai/+server.ts",
    start_line: 24,
    end_line: 35,
    confidence: "medium",
    scanner_sources: ["NOPE rules"],
    status: "suppressed",
    remediation: "Add per-user budget counters before the model call and expire the suppression after rollout.",
    test_guidance: "Exercise repeated requests until the budget is exhausted and assert a 429 response.",
    evidence: [
      { source: "NOPE rules", file: "Raqm/apps/web/src/routes/api/ai/+server.ts", line: 29, snippet: "await qwen.chat(messages)", message: "Model call lacks a mapped budget guard." },
    ],
  },
  {
    id: "fnd_stage8_cookie",
    fingerprint: "fp-stage8-cookie",
    severity: "high" as const,
    title: "Session cookie missing secure attribute",
    description: "A login flow sets a session cookie without the secure flag in a production path.",
    category: "Authentication",
    affected_file: "Raqm/apps/web/src/routes/login/+server.ts",
    start_line: 61,
    end_line: 67,
    confidence: "high",
    scanner_sources: ["NOPE rules"],
    status: "reintroduced",
    remediation: "Set secure cookies in production and add an environment-sensitive regression test.",
    test_guidance: "Assert production cookie attributes include HttpOnly, SameSite, and Secure.",
    evidence: [
      { source: "NOPE rules", file: "Raqm/apps/web/src/routes/login/+server.ts", line: 63, snippet: "cookies.set('session', token, { httpOnly: true })", message: "Secure flag missing in production cookie path." },
    ],
  },
];

const graph = {
  nodes: [
    { id: "entry-root", label: "PAGE /", kind: "entry point" },
    { id: "entry-app", label: "PAGE /app", kind: "entry point" },
    { id: "entry-invoice", label: "GET /app/invoices/:id", kind: "entry point" },
    { id: "file-layout", label: "Raqm/apps/web/src/routes/+layout.svelte", kind: "file", file: "Raqm/apps/web/src/routes/+layout.svelte" },
    { id: "file-page", label: "Raqm/apps/web/src/routes/app/+page.svelte", kind: "file", file: "Raqm/apps/web/src/routes/app/+page.svelte" },
    { id: "file-invoice", label: "Raqm/apps/web/src/routes/app/invoices/[id]/+server.ts", kind: "file", file: "Raqm/apps/web/src/routes/app/invoices/[id]/+server.ts" },
    { id: "db-invoice", label: "db.invoice.findUnique", kind: "database", risk: "critical" as const },
    { id: "risk-owner", label: "Missing ownership check", kind: "authorization", risk: "critical" as const },
  ],
  edges: [
    { source: "entry-root", target: "file-layout", relationship: "handled by" },
    { source: "entry-app", target: "file-page", relationship: "handled by" },
    { source: "entry-invoice", target: "file-invoice", relationship: "handled by" },
    { source: "file-invoice", target: "db-invoice", relationship: "retrieves data from" },
    { source: "file-invoice", target: "risk-owner", relationship: "may reach" },
  ],
};

const scaffold = [
  "dir:Raqm/apps/web/src/routes",
  "dir:Raqm/apps/web/src/routes/app",
  "dir:Raqm/apps/web/src/lib",
  "dir:Raqm/supabase",
  "dir:Raqm/docker",
  "file:Raqm/apps/web/src/routes/+layout.svelte",
  "file:Raqm/apps/web/src/routes/+page.svelte",
  "file:Raqm/apps/web/src/routes/app/+layout.svelte",
  "file:Raqm/apps/web/src/routes/app/+page.svelte",
  "file:Raqm/apps/web/src/routes/app/invoices/[id]/+server.ts",
  "file:Raqm/apps/web/src/routes/app/assets/+page.svelte",
  "file:Raqm/apps/web/src/lib/crypto-vault.js",
  "file:Raqm/apps/web/package-lock.json",
  "file:Raqm/supabase/policies.sql",
  "file:Raqm/docker/web.Dockerfile",
];

function scan(id: string, status: string, verdict: string, score: number, completed = true): Scan {
  return {
    id,
    project_id: E2E_PROJECT_ID,
    status,
    mode: "full",
    verdict,
    score,
    coverage_percent: status === "failed" ? 42 : 70,
    repository_name: id === E2E_SCAN_RUNNING ? "Stage8-running.zip" : "Stage8-app.zip",
    target_url: "https://stage8.example.test",
    branch: "main",
    commit_sha: "stage8fixture",
    started_at: completed ? "2026-07-18T09:45:00.000Z" : now,
    completed_at: completed ? "2026-07-18T09:48:00.000Z" : null,
    findings: status === "failed" ? findings.slice(0, 2) : findings,
    coverage: [
      { domain: "Secrets", status: "Verified", scanners: ["NOPE rules", "Gitleaks"], notes: "Secret rules and scanner artifacts are present." },
      { domain: "Authentication", status: "Verified", scanners: ["NOPE rules"], notes: "Session and cookie paths were checked." },
      { domain: "Authorization", status: "Partial", scanners: ["NOPE rules", "Graph validator"], notes: "Finding-centered graph evidence is available for ID lookups." },
      { domain: "Dependencies", status: "Verified", scanners: ["npm audit", "OSV-Scanner"], notes: "Lockfile advisory data was parsed." },
      { domain: "Dynamic testing", status: "Partial", scanners: ["ZAP baseline"], notes: "Unauthenticated dynamic coverage was stored." },
      { domain: "Qwen AI review", status: "Verified", scanners: ["Qwen"], notes: "Cached Stage 8 action responses are available." },
    ],
    stack: [
      { technology: "SvelteKit", category: "frontend", confidence: "high", evidence: ["src/routes"] },
      { technology: "Supabase", category: "data", confidence: "medium", evidence: ["supabase/policies.sql"] },
    ],
    scanner_runs: [
      { scanner: "NOPE rules", status: "passed", message: "Rules completed.", findings_count: 5, coverage_categories: ["Secrets", "Authorization", "AI cost abuse"] },
      { scanner: "Gitleaks", status: "passed", message: "Secret scan completed.", findings_count: 1, coverage_categories: ["Secrets"] },
      { scanner: "ZAP baseline", status: status === "partial" ? "partial" : "passed", message: "Dynamic coverage captured.", findings_count: 1, coverage_categories: ["Dynamic testing"] },
      { scanner: "Qwen", status: "passed", message: "Focused evidence reviewed.", findings_count: 2, coverage_categories: ["Qwen AI review"] },
    ],
    repository_scaffold: scaffold,
    repository_scaffold_similarity: 92,
    code_graph: graph,
    ai_review: { status: "Verified", provider: "Qwen", model: "qwen3-8b-q4-k-m", message: "Focused evidence reviewed and cached." },
  };
}

export const e2eProjects: Project[] = [
  { id: E2E_PROJECT_ID, name: "Stage 8 Workspace", repository: "stage8/repo", target_url: "https://stage8.example.test", created_at: now },
  { id: "project_mobile", name: "Mobile Smoke", repository: "mobile/app", target_url: "https://mobile.example.test", created_at: now },
];

export const e2eScans: Scan[] = [
  scan(E2E_SCAN_RUNNING, "running", "Running deterministic evidence scan.", 31, false),
  scan(E2E_SCAN_COMPLETED, "completed", "NOPE. Do not ship this.", 38),
  scan(E2E_SCAN_PARTIAL, "partial", "Maybe. Coverage is incomplete.", 55),
  scan(E2E_SCAN_FAILED, "failed", "Failed safely. Deterministic results preserved.", 0),
];

export function e2eFindings(scanId: string, searchParams?: URLSearchParams): FindingsResult {
  const query = (searchParams?.get("query") ?? "").toLowerCase();
  const severity = searchParams?.get("severity") ?? "";
  const status = searchParams?.get("status") ?? "";
  const items = findings.filter((finding) => {
    if (severity && finding.severity !== severity) return false;
    if (status && finding.status !== status) return false;
    if (query && !`${finding.title} ${finding.affected_file ?? ""} ${finding.category}`.toLowerCase().includes(query)) return false;
    return true;
  });
  return { scan_id: scanId, total: items.length, page: 1, page_size: 100, pages: 1, sort: "severity", direction: "asc", filters: {}, items };
}

export function e2eFindingDetail(_scanId: string, findingId: string): FindingDetail | null {
  const finding = findings.find((item) => item.id === findingId) ?? findings[0];
  if (!finding) return null;
  return {
    finding,
    evidence: finding.evidence ?? [],
    source: {
      file: finding.affected_file ?? "unknown",
      start_line: finding.start_line ?? 1,
      end_line: finding.end_line ?? finding.start_line ?? 1,
      language: "typescript",
      code: "export async function load(event) {\n  const id = event.params.id;\n  return db.invoice.findUnique({ where: { id } });\n}",
      highlighted_lines: [finding.start_line ?? 1],
      available: Boolean(finding.affected_file),
      message: "Deterministic Stage 8 source fixture.",
    },
    code_flow: { available: true, nodes: graph.nodes, edges: graph.edges, message: "Fixture graph flow." },
    history: [
      { event: "created", at: now, data: { scanner: finding.scanner_sources[0] } },
      { event: "reviewed", at: now, data: { state: finding.status } },
    ],
    tabs: ["overview", "evidence", "code", "code_flow", "fix", "tests", "history"],
  };
}

export const e2eBaselines: SecurityBaseline[] = [
  { id: "baseline_stage8", project_id: E2E_PROJECT_ID, scan_id: E2E_SCAN_PARTIAL, name: "Stage 8 baseline", created_at: "2026-07-18T09:00:00.000Z", data: { score: 55 } },
];

export const e2eComparison: ScanComparison = {
  current_scan_id: E2E_SCAN_COMPLETED,
  reference_scan_id: E2E_SCAN_PARTIAL,
  baseline_id: "baseline_stage8",
  new: findings.slice(0, 2),
  fixed: [{ title: "Debug endpoint removed" }],
  reintroduced: findings.filter((finding) => finding.status === "reintroduced"),
  unchanged: findings.slice(2, 5),
  severity_changes: [],
  confidence_changes: [],
  coverage_difference: [{ domain: "Dynamic testing", before: 35, after: 70 }],
  scanner_difference: [],
  stack_difference: [],
  drift_events: [
    { type: "new_critical", severity: "critical", message: "Invoice lookup risk is new relative to the baseline." },
    { type: "coverage_improved", severity: "info", message: "Dynamic testing coverage increased." },
  ],
  incremental_scope: { mode: "folder", changed_files: ["src/routes/app/invoices/[id]/+server.ts"], relevant_scanners: ["NOPE rules", "ZAP baseline"], requires_full_scan: false, note: "Comparable Stage 8 fixture scans." },
  summary: { new: 2, fixed: 1, reintroduced: 1, coverage_drift: 1 },
};

export const e2eModelSettings: ModelSettings = {
  provider: "local-qwen",
  model_name: "Qwen3-8B-Q4_K_M",
  model_file_path: "D:/Desktop/Model/Qwen3-8B-Q4_K_M.gguf",
  runtime_endpoint: "http://nope-ai:8080/v1/chat/completions",
  context_length: 8192,
  maximum_output_tokens: 900,
  gpu_layer_count: 28,
  maximum_gpu_memory_target_mb: 5000,
  batch_size: 256,
  threads: 8,
  parallel: 1,
  request_timeout: 90,
  rag: { maximum_files: 8, maximum_tokens: 3500, maximum_graph_depth: 2, chunk_characters: 1800, embeddings_required: false },
};

export const e2eSystemSettings: SystemSettings = {
  qwen_endpoint: "http://nope-ai:8080/v1/chat/completions",
  runtime: "llama.cpp",
  context: 8192,
  gpu_layers: 28,
  timeout: 90,
  output_limit: 900,
  concurrency: 1,
  scanner_enabled: { "NOPE rules": true, Gitleaks: true, Semgrep: true, "ZAP baseline": true },
  scanner_timeout: 180,
  default_scan_mode: "full",
  retention_days: 30,
  report_defaults: ["pdf", "md", "json", "sarif"],
  artifact_limit_mb: 64,
  sandbox_limits: { network: "disabled_by_default", memory_mb: 1024, timeout_seconds: 180 },
};

export const e2eProjectSettings: ProjectSettings = {
  project_id: E2E_PROJECT_ID,
  target_url: "https://stage8.example.test",
  approved_hosts: ["stage8.example.test"],
  excluded_paths: ["node_modules", ".git"],
  scanner_overrides: {},
  scan_depth: "full",
  test_identities: [{ label: "ghost tester", username: "stage8@example.test", notes: "fixture account" }],
  test_identities_configured: true,
  baseline_id: "baseline_stage8",
  repository_metadata: { label: "stage8/repo" },
  authorization_confirmed: true,
  rag_limits: { maximum_files: 8, maximum_tokens: 3500, maximum_graph_depth: 2 },
};

export const e2eGitHubStatus: GitHubStatus = {
  provider: "github",
  status: "Credentials Needed",
  credential_state: { app_id: false, private_key: false, webhook_secret: false },
  message: "Stage 8 fixture keeps GitHub integration blocked until credentials are configured.",
  repositories: [],
};

export const e2eAIHealth: AIHealth = {
  status: "ok",
  message: "Stage 8 fixture AI health.",
  latency_ms: 320,
  runtime: "llama.cpp",
  model: "Qwen3-8B-Q4_K_M",
  model_path: "D:/Desktop/Model/Qwen3-8B-Q4_K_M.gguf",
  gpu: { status: "bounded", layers: 28, memory_target_mb: 5000, message: "Fixture VRAM target remains under 5 GB." },
};
