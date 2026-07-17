"use client";

import { useEffect, useMemo, useState } from "react";

import type { Finding } from "@/lib/types";

type AIAction = "explain" | "challenge" | "fix" | "test";
type AIActionResult = {
  status: string;
  message: string;
  model?: string;
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
  ["test", "Test"],
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
  test: {
    title: "Regression plan",
    evidence: "Coverage target",
    reasoning: "Cases to prove",
    recommendation: "Tests to add",
  },
};

function StableRevealText({ text }: { text: string }) {
  return <span className="answer-reveal-text">{text}</span>;
}

export function AIFindingActions({ finding }: { finding: Finding }) {
  const [activeAction, setActiveAction] = useState<AIAction | null>(null);
  const [selectedAction, setSelectedAction] = useState<AIAction | null>(null);
  const [results, setResults] = useState<Partial<Record<AIAction, AIActionResult>>>({});
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

  function cacheResults(nextResults: Partial<Record<AIAction, AIActionResult>>) {
    try {
      window.localStorage.setItem(cacheKey, JSON.stringify({ expiresAt: Date.now() + CACHE_TTL_MS, results: nextResults }));
    } catch {
      // Cache failure should never block the analysis action.
    }
  }

  async function runAction(action: AIAction) {
    if (results[action]) {
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
        body: JSON.stringify({ action, finding }),
      });
      const data = await response.json();
      if (!response.ok || data.status === "Failed") {
        throw new Error(data.message ?? "Qwen action failed.");
      }
      setResults((current) => {
        const next = { ...current, [action]: data };
        cacheResults(next);
        return next;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Qwen action failed.");
    } finally {
      setActiveAction(null);
    }
  }

  const result = selectedAction ? results[selectedAction] : null;
  const structured = result?.result;
  const labels = selectedAction ? actionCopy[selectedAction] : null;

  return (
    <div className="ai-actions">
      <div className="button-row">
        {actionLabels.map(([action, label]) => (
          <button className={`button ai-action-button${selectedAction === action ? " active-ai-action" : ""}`} key={action} type="button" onClick={() => runAction(action)} disabled={activeAction !== null}>
            {activeAction === action ? "Thinking..." : label}
          </button>
        ))}
      </div>
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
          <span className="mono ai-generated-label">Gen. by Qwen</span>
        </div>
      ) : null}
    </div>
  );
}
