"use client";

import { useMemo, useState } from "react";
import { severityClass } from "@/lib/nope-data";
import type { Finding } from "@/lib/types";

const BATCH_SIZE = 7;

export function FindingTable({
  findings,
  scanId,
  selectedId,
  search,
  total,
}: {
  findings: Finding[];
  scanId?: string;
  selectedId?: string;
  search?: URLSearchParams;
  total?: number;
}) {
  const [visibleCount, setVisibleCount] = useState(BATCH_SIZE);
  const hrefFor = (finding: Finding) => {
    const params = new URLSearchParams(search?.toString());
    if (scanId) params.set("scan", scanId);
    params.set("finding", finding.id);
    return `/app/projects/local/findings?${params.toString()}`;
  };
  const visibleFindings = useMemo(() => findings.slice(0, visibleCount), [findings, visibleCount]);
  const resultTotal = total ?? findings.length;
  const canLoadMore = visibleFindings.length < findings.length;

  function openFinding(finding: Finding) {
    if (!scanId) return;
    window.location.assign(hrefFor(finding));
  }

  return (
    <div className="app-panel">
      <div className="panel-title">
        <h2>Findings</h2>
        <span className="mono muted">{Math.min(visibleFindings.length, resultTotal)} of {resultTotal}</span>
      </div>
      <table className="table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Finding</th>
            <th>Location</th>
            <th>Evidence</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {findings.length === 0 ? (
            <tr>
              <td colSpan={5}>No findings yet. No scan evidence has been produced.</td>
            </tr>
          ) : (
            visibleFindings.map((finding) => (
              <tr
                className={`interactive-row clickable-finding-row${finding.id === selectedId ? " selected-row" : ""}`}
                key={finding.id}
                onClick={() => openFinding(finding)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    openFinding(finding);
                  }
                }}
                role={scanId ? "link" : undefined}
                tabIndex={scanId ? 0 : undefined}
              >
                <td>
                  <span className={severityClass(finding.severity)}>{finding.severity}</span>
                </td>
                <td>
                  <strong>{finding.title}</strong>
                  <br />
                  <span className="muted">{finding.category} / {finding.confidence}</span>
                </td>
                <td className="mono">{finding.affected_file ?? finding.affected_route ?? "n/a"}</td>
                <td>{finding.scanner_sources.join(" + ") || finding.raw_artifact_id || "Evidence"}</td>
                <td>{finding.status}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
      {findings.length > 0 ? (
        <div className="finding-table-footer">
          <span className="mono muted">{visibleFindings.length} shown{resultTotal > findings.length ? ` / ${findings.length} loaded from ${resultTotal}` : ""}</span>
          {canLoadMore ? (
            <button className="button-secondary" type="button" onClick={() => setVisibleCount((count) => Math.min(count + BATCH_SIZE, findings.length))}>
              Load more
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
