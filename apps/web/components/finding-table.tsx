"use client";

import { useEffect, useMemo, useState } from "react";
import type { Finding } from "@/lib/types";

const BATCH_SIZE = 7;

function severityClass(severity: string) {
  return `severity-pill severity-${severity}`;
}

function lineFor(finding: Finding) {
  return finding.start_line ?? finding.evidence?.find((item) => item.line)?.line ?? null;
}

function lineRangeFor(finding: Finding) {
  const line = lineFor(finding);
  if (!line) return null;
  if (finding.end_line && finding.end_line !== line) return `lines ${line}-${finding.end_line}`;
  return `line ${line}`;
}

function SlashMeta({ items }: { items: Array<string | null | undefined> }) {
  const visible = items.filter((item): item is string => Boolean(item));
  return (
    <>
      {visible.map((item, index) => (
        <span key={`${item}-${index}`}>
          {index > 0 ? <span className="hot-slash"> / </span> : null}
          {item}
        </span>
      ))}
    </>
  );
}

export function FindingTable({
  findings,
  scanId,
  selectedId,
  searchQuery,
  total,
}: {
  findings: Finding[];
  scanId?: string;
  selectedId?: string;
  searchQuery?: string;
  total?: number;
}) {
  const search = useMemo(() => new URLSearchParams(searchQuery), [searchQuery]);
  const requestedVisible = Number(search.get("shown") ?? BATCH_SIZE);
  const initialVisibleCount = Number.isFinite(requestedVisible) ? Math.max(BATCH_SIZE, requestedVisible) : BATCH_SIZE;
  const [shownCount, setShownCount] = useState(initialVisibleCount);
  const [newBatchStart, setNewBatchStart] = useState<number | null>(null);

  useEffect(() => {
    setShownCount(initialVisibleCount);
    setNewBatchStart(null);
  }, [initialVisibleCount, findings]);

  const hrefFor = (finding: Finding) => {
    const params = new URLSearchParams(search.toString());
    if (scanId) params.set("scan", scanId);
    params.set("finding", finding.id);
    params.delete("detail");
    return `/app/projects/local/findings?${params.toString()}`;
  };
  const clampedShownCount = Math.min(shownCount, findings.length);
  const visibleFindings = useMemo(() => findings.slice(0, clampedShownCount), [findings, clampedShownCount]);
  const resultTotal = total ?? findings.length;
  const canLoadMore = visibleFindings.length < findings.length;

  function openFinding(finding: Finding) {
    if (!scanId) return;
    window.location.assign(hrefFor(finding));
  }

  function loadMore() {
    const currentCount = Math.min(shownCount, findings.length);
    setNewBatchStart(currentCount);
    setShownCount(Math.min(currentCount + BATCH_SIZE, findings.length));
  }

  return (
    <div className="app-panel">
      <div className="panel-title">
        <h2>Findings</h2>
        <span className="mono muted">{Math.min(visibleFindings.length, resultTotal)} of {resultTotal}</span>
      </div>
      <table className="table finding-table">
        <colgroup>
          <col className="severity-column" />
          <col className="finding-column" />
          <col className="location-column" />
          <col className="evidence-column" />
          <col className="status-column" />
        </colgroup>
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
            visibleFindings.map((finding, index) => (
              <tr
                className={`interactive-row clickable-finding-row${finding.id === selectedId ? " selected-row" : ""}${newBatchStart !== null && index >= newBatchStart ? " new-finding-row" : ""}`}
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
                <td className="finding-title-cell">
                  <strong>{finding.title}</strong>
                  <br />
                  <span className="muted">
                    <SlashMeta items={[finding.category, finding.confidence, lineRangeFor(finding)]} />
                  </span>
                </td>
                <td className="mono location-cell">{finding.affected_file ?? finding.affected_route ?? "n/a"}</td>
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
            <button className="load-more-button" type="button" onClick={loadMore}>
              <span>Load more</span>
              <span className="mono">{Math.min(visibleFindings.length + BATCH_SIZE, findings.length)}/{findings.length}</span>
            </button>
          ) : (
            <span className="mono muted">All visible</span>
          )}
        </div>
      ) : null}
    </div>
  );
}
