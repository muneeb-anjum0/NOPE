export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  id: string;
  schema_version?: string;
  fingerprint?: string;
  original_fingerprint?: string | null;
  correlation_id?: string | null;
  severity: Severity;
  title: string;
  description?: string;
  category: string;
  cwe?: string | null;
  owasp?: string | null;
  affected_file?: string | null;
  affected_route?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  symbol?: string | null;
  package?: string | null;
  cve?: string | null;
  raw_artifact_id?: string | null;
  source_metadata?: Record<string, unknown>;
  nope_rule_id?: string | null;
  original_rule_id?: string | null;
  confidence: string;
  scanner_sources: string[];
  status: string;
  verification_state?: string;
  ai_review_state?: string;
  first_seen?: string;
  last_seen?: string;
  recurrence_count?: number;
  baseline_state?: string;
  suppression?: { reason: string; user: string; actor?: string | null; date: string; expiry?: string | null; scope: string } | null;
  suppression_expired_at?: string | null;
  lifecycle_version?: number;
  fix_available?: boolean;
  verified?: boolean;
  test_guidance?: string | null;
  remediation: string;
  evidence?: Array<{ source: string; file?: string | null; line?: number | null; snippet?: string | null; message: string }>;
};

export type FindingsResult = {
  scan_id: string;
  total: number;
  page: number;
  page_size: number;
  pages: number;
  sort: string;
  direction: "asc" | "desc";
  filters: Record<string, unknown>;
  items: Finding[];
};

export type FindingDetail = {
  finding: Finding;
  evidence: Array<Record<string, unknown>>;
  source?: {
    file: string;
    start_line: number;
    end_line: number;
    language: string;
    code: string;
    highlighted_lines: number[];
    available: boolean;
    message: string;
  } | null;
  code_flow: {
    available: boolean;
    nodes: Array<{ id: string; label: string; kind: string; file?: string | null; risk?: Severity | null }>;
    edges: Array<{ source: string; target: string; relationship: string }>;
    message: string;
  };
  history: Array<{ event: string; at: string; data: Record<string, unknown> }>;
  tabs: string[];
};

export type SecurityBaseline = {
  id: string;
  project_id?: string | null;
  scan_id?: string | null;
  name: string;
  created_at: string;
  data: Record<string, unknown>;
};

export type ScanComparison = {
  reference_scan_id?: string | null;
  current_scan_id: string;
  baseline_id?: string | null;
  new: Finding[];
  fixed: Array<Record<string, unknown>>;
  reintroduced: Finding[];
  unchanged: Finding[];
  severity_changes: Array<Record<string, unknown>>;
  confidence_changes: Array<Record<string, unknown>>;
  coverage_difference: Array<Record<string, unknown>>;
  scanner_difference: Array<Record<string, unknown>>;
  stack_difference: Array<Record<string, unknown>>;
  drift_events: Array<{ type: string; severity?: string | null; message: string }>;
  incremental_scope: {
    mode?: string;
    changed_files?: string[];
    relevant_scanners?: string[];
    requires_full_scan?: boolean;
    note?: string;
  };
  summary: Record<string, number>;
};

export type CoverageRecord = {
  domain: string;
  status: "Verified" | "Partial" | "Not tested" | "Failed" | "Not applicable";
  scanners: string[];
  notes: string;
};

export type Scan = {
  id: string;
  project_id?: string | null;
  status: string;
  mode: "url" | "repository" | "full";
  verdict: string;
  score: number;
  coverage_percent: number;
  target_url?: string | null;
  repository_name?: string | null;
  repository_scaffold?: string[];
  repository_scaffold_similarity?: number | null;
  branch?: string | null;
  commit_sha?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  findings: Finding[];
  coverage: CoverageRecord[];
  stack?: Array<{ technology: string; category: string; confidence?: string; evidence?: string[] }>;
  scanner_runs: Array<{ scanner: string; status: string; message: string; findings_count: number; coverage_categories: string[] }>;
  code_graph: {
    nodes: Array<{ id: string; label: string; kind: string; file?: string | null; risk?: Severity | null }>;
    edges?: Array<{ source: string; target: string; relationship: string }>;
  };
  ai_review: { status: string; provider: string; model?: string | null; message: string };
  rules_v2?: RulesV2Summary | null;
};

export type RulesV2Evidence = {
  kind?: string;
  file?: string | null;
  line?: number | null;
  end_line?: number | null;
  route?: string | null;
  symbol?: string | null;
  source?: string;
  message?: string;
  snippet?: string | null;
  strength?: string;
  metadata?: Record<string, unknown>;
};

export type RulesV2Candidate = {
  candidate_id: string;
  rule_id: string;
  rule_version?: string;
  file?: string | null;
  line?: number | null;
  end_line?: number | null;
  route?: string | null;
  source_type?: string;
  family?: string;
  preliminary_severity?: string;
  preliminary_confidence?: string;
  evidence?: RulesV2Evidence[];
  missing_evidence?: string[];
  contradictory_evidence?: string[];
  safe_pattern_evidence?: string[];
  graph_references?: string[];
  scanner_references?: string[];
};

export type RulesV2Decision = {
  candidate_id: string;
  rule_id: string;
  rule_version?: string;
  result: "promoted" | "withheld" | "rejected" | "needs_manual_review" | "not_applicable" | string;
  confidence?: string;
  evidence_strength?: string;
  reason?: string;
  machine_reason?: string;
  missing_evidence?: string[];
  contradictory_evidence?: string[];
  correlation_path?: string[];
  suggested_manual_verification?: string | null;
};

export type RulesV2Summary = {
  scan_id?: string;
  version?: string | null;
  catalog?: Record<string, unknown>;
  coverage?: {
    candidate_count?: number;
    promoted?: number;
    withheld?: number;
    rejected?: number;
    needs_manual_review?: number;
    not_applicable?: number;
    by_family?: Record<string, Record<string, number>>;
  };
  metrics?: Record<string, unknown>;
  failures?: string[];
};

export type RulesV2CandidateResult = {
  scan_id: string;
  page: number;
  page_size: number;
  total: number;
  items: Array<{ candidate: RulesV2Candidate; decision: RulesV2Decision }>;
};

export type Project = {
  id: string;
  name: string;
  repository?: string | null;
  target_url?: string | null;
  created_at?: string;
};

export type SystemSettings = {
  qwen_endpoint: string;
  runtime: "llama.cpp" | "disabled" | string;
  context: number;
  gpu_layers: number;
  timeout: number;
  output_limit: number;
  concurrency: number;
  scanner_enabled: Record<string, boolean>;
  scanner_timeout: number;
  default_scan_mode: "url" | "repository" | "full";
  retention_days: number;
  report_defaults: string[];
  artifact_limit_mb: number;
  sandbox_limits: Record<string, unknown>;
};

export type ProjectSettings = {
  project_id: string;
  target_url?: string | null;
  approved_hosts: string[];
  excluded_paths: string[];
  scanner_overrides: Record<string, boolean>;
  scan_depth: "quick" | "full" | "deep";
  test_identities: Array<{ label: string; username?: string | null; notes?: string | null }>;
  test_identities_configured: boolean;
  baseline_id?: string | null;
  repository_metadata: Record<string, unknown>;
  authorization_confirmed: boolean;
  rag_limits: Record<string, number>;
};

export type GitHubStatus = {
  provider: "github" | string;
  status: string;
  credential_state: Record<string, boolean>;
  connection_id?: string | null;
  callback_url?: string | null;
  selected_repository?: string | null;
  selected_branch?: string | null;
  token_expires_at?: string | null;
  message: string;
  repositories: Array<Record<string, unknown>>;
};

export type ModelSettings = {
  provider: string;
  model_name: string;
  model_file_path: string;
  runtime_endpoint: string;
  context_length: number;
  maximum_output_tokens: number;
  gpu_layer_count: number;
  maximum_gpu_memory_target_mb: number;
  batch_size?: number;
  threads?: number;
  parallel?: number;
  request_timeout?: number;
  rag?: {
    maximum_files: number;
    maximum_tokens: number;
    maximum_graph_depth: number;
    chunk_characters: number;
    embeddings_required: boolean;
  };
};

export type AIHealth = {
  status: string;
  message?: string;
  latency_ms?: number;
  runtime?: string;
  model?: string;
  model_path?: string;
  gpu?: {
    status: string;
    layers: number;
    memory_target_mb: number;
    message: string;
  };
};
