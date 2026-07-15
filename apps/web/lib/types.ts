export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  id: string;
  fingerprint?: string;
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

export type CoverageRecord = {
  domain: string;
  status: "Verified" | "Partial" | "Not tested" | "Failed" | "Not applicable";
  scanners: string[];
  notes: string;
};

export type Scan = {
  id: string;
  status: string;
  mode: "url" | "repository" | "full";
  verdict: string;
  score: number;
  coverage_percent: number;
  target_url?: string | null;
  repository_name?: string | null;
  branch?: string | null;
  commit_sha?: string | null;
  findings: Finding[];
  coverage: CoverageRecord[];
  scanner_runs: Array<{ scanner: string; status: string; message: string; findings_count: number; coverage_categories: string[] }>;
  code_graph: { nodes: Array<{ id: string; label: string; kind: string; file?: string | null; risk?: Severity | null }> };
  ai_review: { status: string; provider: string; model?: string | null; message: string };
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
