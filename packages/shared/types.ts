export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type CoverageStatus = "Verified" | "Partial" | "Not tested" | "Failed" | "Not applicable";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: string;
  category: string;
  affected_file?: string | null;
  affected_route?: string | null;
  scanner_sources: string[];
  remediation: string;
  status: string;
  verified: boolean;
  fix_available: boolean;
}

export interface CoverageRecord {
  domain: string;
  status: CoverageStatus;
  scanners: string[];
  notes: string;
}

export interface Scan {
  id: string;
  mode: "url" | "repository" | "full";
  status: string;
  verdict: string;
  score: number;
  coverage_percent: number;
  target_url?: string | null;
  repository_name?: string | null;
  branch?: string | null;
  commit_sha?: string | null;
  findings: Finding[];
  coverage: CoverageRecord[];
  scanner_runs: Array<{
    scanner: string;
    status: "passed" | "failed" | "skipped";
    message: string;
    findings_count: number;
    coverage_categories: string[];
  }>;
}
