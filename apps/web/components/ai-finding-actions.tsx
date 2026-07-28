"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { Finding } from "@/lib/types";

type AIAction = "explain" | "challenge" | "fix" | "regression_test" | "patch_review" | "investigate";
type InvestigationStatement = { status: "Verified" | "Supported" | "Likely" | "Possible" | "Unknown"; text: string; citations: string[] };
type InvestigationReport = {
  version: string;
  mode: string;
  finding_id: string;
  finding_fingerprint: string;
  evidence_references: Array<Record<string, unknown>>;
  related_finding_records?: Array<Record<string, unknown>>;
  [key: string]: unknown;
};
type AIActionResult = {
  status: string;
  state?: "queued" | "running" | "completed" | "failed" | "cancelled";
  message: string;
  job_id?: string;
  model?: string;
  cached?: boolean;
  latency_ms?: number | null;
  context_chunks?: number;
  result?: {
    summary: string;
    evidence?: string[];
    reasoning?: string;
    recommendation: string;
    confidence: string;
    risk?: string | null;
    investigation_report?: InvestigationReport | null;
  } | null;
};

const actionLabels: Array<[AIAction, string]> = [
  ["explain", "Explain"],
  ["challenge", "Challenge"],
  ["fix", "Fix"],
  ["regression_test", "Test"],
  ["patch_review", "Patch Review"],
  ["investigate", "Investigate"],
];

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_VERSION = "v2";

type CachedResults = {
  expiresAt: number;
  results: Partial<Record<AIAction, AIActionResult>>;
};

const actionCopy: Record<AIAction, { title: string; reasoning: string; recommendation: string; evidence: string }> = {
  explain: {
    title: "What this means",
    evidence: "Evidence used",
    reasoning: "Why it matters",
    recommendation: "Inspect next",
  },
  challenge: {
    title: "Skeptical review",
    evidence: "Support and gaps",
    reasoning: "Assumptions to verify",
    recommendation: "Confirm or dismiss",
  },
  fix: {
    title: "Patch direction",
    evidence: "Patch target",
    reasoning: "Why this fixes it",
    recommendation: "Patch steps",
  },
  regression_test: {
    title: "Regression plan",
    evidence: "Coverage target",
    reasoning: "Cases to prove",
    recommendation: "Tests to add",
  },
  patch_review: {
    title: "Patch review",
    evidence: "Review evidence",
    reasoning: "Bypass checks",
    recommendation: "Review checklist",
  },
  investigate: {
    title: "Investigation report",
    evidence: "Evidence references",
    reasoning: "Investigation notes",
    recommendation: "Developer path",
  },
};

function StableRevealText({ text }: { text: string }) {
  return <span className="answer-reveal-text">{text}</span>;
}

const investigationSections = [
  "summary",
  "root_cause",
  "evidence",
  "repository_context",
  "attack_flow",
  "trust_boundary",
  "exploitability",
  "prerequisites",
  "potential_impact",
  "why_rules_promoted_it",
  "confidence_explanation",
  "developer_fix",
  "verification_steps",
  "false_positive_considerations",
  "related_findings",
  "related_files",
  "relevant_routes",
  "relevant_database_models",
  "relevant_policies",
  "relevant_auth_helpers",
  "relevant_middleware",
  "relevant_storage",
  "framework_notes",
  "unknowns",
  "ai_reasoning_notes",
];

function sectionTitle(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function statementList(value: unknown): InvestigationStatement[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is InvestigationStatement => Boolean(item && typeof item === "object" && "text" in item && "status" in item));
}

function InvestigationReportView({ report, jobId }: { report: InvestigationReport; jobId?: string }) {
  return (
    <div className="investigation-report">
      <div className="investigation-report-head">
        <div>
          <span className="ai-result-label">AI Investigation Engine</span>
          <strong>{report.mode ?? "Security Engineer"} / {report.version ?? "stage15"}</strong>
        </div>
        {jobId ? (
          <div className="button-row compact-actions">
            {(["json", "md", "pdf"] as const).map((fmt) => (
              <a className="button-secondary" key={fmt} href={`/api/ai/investigation-export?job=${encodeURIComponent(jobId)}&format=${fmt}`}>
                {fmt.toUpperCase()}
              </a>
            ))}
          </div>
        ) : null}
      </div>
      <div className="investigation-grid">
        {investigationSections.map((section) => {
          const statements = statementList(report[section]);
          if (statements.length === 0) return null;
          return (
            <details className="investigation-section" key={section} open={section === "summary" || section === "attack_flow"}>
              <summary>{sectionTitle(section)}</summary>
              <ul>
                {statements.map((statement, index) => (
                  <li key={`${section}-${index}`}>
                    <span className={`investigation-status status-${statement.status.toLowerCase()}`}>{statement.status}</span>
                    <span>{statement.text}</span>
                    {statement.citations?.length ? <small>{statement.citations.join(", ")}</small> : null}
                  </li>
                ))}
              </ul>
            </details>
          );
        })}
      </div>
      <details className="investigation-section">
        <summary>Citations</summary>
        <ul>
          {(report.evidence_references ?? []).map((reference, index) => (
            <li key={String(reference.id ?? index)}>
              <span className="investigation-status status-verified">{String(reference.id ?? `ref-${index + 1}`)}</span>
              <span>{String(reference.file ?? reference.route ?? reference.title ?? reference.source ?? "Evidence")}</span>
              {reference.line ? <small>line {String(reference.line)}</small> : null}
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

export function AIFindingActions({ finding, scanId }: { finding: Finding; scanId?: string }) {
  const [activeAction, setActiveAction] = useState<AIAction | null>(null);
  const [selectedAction, setSelectedAction] = useState<AIAction | null>(null);
  const [results, setResults] = useState<Partial<Record<AIAction, AIActionResult>>>({});
  const [jobs, setJobs] = useState<Partial<Record<AIAction, string>>>({});
  const [error, setError] = useState<string | null>(null);
  const cacheKey = useMemo(() => `nope:ai-finding-actions:${CACHE_VERSION}:${finding.id}:${finding.fingerprint ?? "no-fingerprint"}`, [finding.fingerprint, finding.id]);

  useEffect(() => {
    try {
      const cached = window.localStorage.getItem(cacheKey);
      if (!cached) {
        setResults({});
        setSelectedAction(null);
        return;
      }
      const parsed = JSON.parse(cached) as CachedResults;
      if (!parsed.expiresAt || parsed.expiresAt <= Date.now()) {
        window.localStorage.removeItem(cacheKey);
        setResults({});
        setSelectedAction(null);
        return;
      }
      setResults(parsed.results ?? {});
      setSelectedAction(null);
    } catch {
      setResults({});
      setSelectedAction(null);
    }
  }, [cacheKey]);

  const cacheResults = useCallback((nextResults: Partial<Record<AIAction, AIActionResult>>) => {
    try {
      window.localStorage.setItem(cacheKey, JSON.stringify({ expiresAt: Date.now() + CACHE_TTL_MS, results: nextResults }));
    } catch {
      // Cache failure should never block the analysis action.
    }
  }, [cacheKey]);

  useEffect(() => {
    const activeJobs = Object.entries(jobs).filter(([, jobId]) => Boolean(jobId)) as Array<[AIAction, string]>;
    if (activeJobs.length === 0) return;
    let cancelled = false;
    const poll = async () => {
      for (const [action, jobId] of activeJobs) {
        try {
          const response = await fetch(`/api/ai/finding-action?job=${encodeURIComponent(jobId)}`, { cache: "no-store" });
          const data = (await response.json()) as AIActionResult;
          if (cancelled) return;
          setResults((current) => {
            const next = { ...current, [action]: data };
            if (data.state === "completed" && data.result) {
              cacheResults(next);
            }
            return next;
          });
          if (["completed", "failed", "cancelled"].includes(data.state ?? "")) {
            setJobs((current) => {
              const next = { ...current };
              delete next[action];
              return next;
            });
            setActiveAction((current) => (current === action ? null : current));
          }
        } catch {
          // Poll errors are transient; the next interval can recover.
        }
      }
    };
    void poll();
    const id = window.setInterval(poll, 1600);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [cacheResults, jobs]);

  async function runAction(action: AIAction) {
    if (results[action]?.state === "completed" && results[action]?.result) {
      setSelectedAction(action);
      setError(null);
      return;
    }
    setActiveAction(action);
    setSelectedAction(action);
    setError(null);
    try {
      const response = await fetch("/api/ai/finding-action", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, finding, scanId, findingId: finding.id }),
      });
      const data = await response.json();
      if (!response.ok || data.state === "failed" || data.status === "Failed") {
        throw new Error(data.message ?? "Qwen action failed.");
      }
      if (data.job_id && ["queued", "running"].includes(data.state)) {
        setJobs((current) => ({ ...current, [action]: data.job_id }));
      }
      setResults((current) => {
        const next = { ...current, [action]: data };
        if (data.state === "completed" && data.result) {
          cacheResults(next);
        }
        return next;
      });
      if (data.state === "completed") {
        setActiveAction(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Qwen action failed.");
      setActiveAction(null);
    }
  }

  async function cancelAction(action: AIAction) {
    const jobId = jobs[action] ?? results[action]?.job_id;
    if (!jobId) return;
    await fetch(`/api/ai/finding-action?job=${encodeURIComponent(jobId)}`, { method: "DELETE" });
  }

  const result = selectedAction ? results[selectedAction] : null;
  const structured = result?.result;
  const labels = selectedAction ? actionCopy[selectedAction] : null;
  const runningState = selectedAction ? results[selectedAction]?.state : null;

  return (
    <div className="ai-actions">
      <div className="button-row">
        {actionLabels.map(([action, label]) => (
          <button className={`button ai-action-button${selectedAction === action ? " active-ai-action" : ""}`} key={action} type="button" onClick={() => runAction(action)} disabled={activeAction !== null && activeAction !== action}>
            {activeAction === action || jobs[action] ? "Running..." : label}
          </button>
        ))}
      </div>
      {selectedAction && runningState && ["queued", "running"].includes(runningState) ? (
        <p className="muted">
          {runningState === "queued" ? "Queued" : "Qwen is writing"}.
          {result?.context_chunks ? ` ${result.context_chunks} evidence chunks.` : null}
          <button className="inline-action" type="button" onClick={() => cancelAction(selectedAction)}>Cancel</button>
        </p>
      ) : null}
      {error ? <p className="muted">{error}</p> : null}
      {structured && labels ? (
        <div className="ai-result">
          <div>
            <span className="ai-result-label">{labels.title}</span>
            <strong><StableRevealText text={structured.summary} /></strong>
          </div>
          {structured.evidence?.length ? (
            <div>
              <span className="ai-result-label">{labels.evidence}</span>
              <ul className="ai-evidence-list">
                {structured.evidence.slice(0, 4).map((item, index) => (
                  <li key={`${item}-${index}`}>
                    <StableRevealText text={item} />
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {structured.reasoning ? (
            <div>
              <span className="ai-result-label">{labels.reasoning}</span>
              <p><StableRevealText text={structured.reasoning} /></p>
            </div>
          ) : null}
          <div>
            <span className="ai-result-label">{labels.recommendation}</span>
            <p><StableRevealText text={structured.recommendation} /></p>
          </div>
          {structured.investigation_report ? <InvestigationReportView report={structured.investigation_report} jobId={result?.job_id} /> : null}
          <span className="mono ai-generated-label">Gen. by Qwen{result?.cached ? " / cached" : ""}{result?.latency_ms ? ` / ${Math.round(result.latency_ms / 1000)}s` : ""}</span>
        </div>
      ) : null}
    </div>
  );
}
