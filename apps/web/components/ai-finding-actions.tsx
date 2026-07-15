"use client";

import { useState } from "react";

import type { Finding } from "@/lib/types";

type AIAction = "explain" | "challenge" | "fix" | "test";
type AIActionResult = {
  status: string;
  message: string;
  model?: string;
  result?: {
    summary: string;
    recommendation: string;
    confidence: string;
  } | null;
};

const actionLabels: Array<[AIAction, string]> = [
  ["explain", "Explain"],
  ["challenge", "Challenge"],
  ["fix", "Fix"],
  ["test", "Test"],
];

export function AIFindingActions({ finding }: { finding: Finding }) {
  const [activeAction, setActiveAction] = useState<AIAction | null>(null);
  const [result, setResult] = useState<AIActionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runAction(action: AIAction) {
    setActiveAction(action);
    setError(null);
    setResult(null);
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
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Qwen action failed.");
    } finally {
      setActiveAction(null);
    }
  }

  const structured = result?.result;

  return (
    <div className="ai-actions">
      <div className="button-row">
        {actionLabels.map(([action, label]) => (
          <button className="button" key={action} type="button" onClick={() => runAction(action)} disabled={activeAction !== null}>
            {activeAction === action ? "Running..." : label}
          </button>
        ))}
      </div>
      {error ? <p className="muted">{error}</p> : null}
      {structured ? (
        <div className="ai-result">
          <strong>{structured.summary}</strong>
          <p>{structured.recommendation}</p>
          <span className="mono muted">{result?.model} / {structured.confidence}</span>
        </div>
      ) : null}
    </div>
  );
}
