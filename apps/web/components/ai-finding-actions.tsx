"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { Finding } from "@/lib/types";

type AIAction = "explain" | "challenge" | "fix" | "regression_test" | "patch_review";
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
  } | null;
};

const actionLabels: Array<[AIAction, string]> = [
  ["explain", "Explain"],
  ["challenge", "Challenge"],
  ["fix", "Fix"],
  ["regression_test", "Test"],
  ["patch_review", "Patch Review"],
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
};

function StableRevealText({ text }: { text: string }) {
  return <span className="answer-reveal-text">{text}</span>;
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
          <span className="mono ai-generated-label">Gen. by Qwen{result?.cached ? " / cached" : ""}{result?.latency_ms ? ` / ${Math.round(result.latency_ms / 1000)}s` : ""}</span>
        </div>
      ) : null}
    </div>
  );
}
