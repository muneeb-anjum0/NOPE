import { severityClass } from "@/lib/nope-data";
import type { Finding } from "@/lib/types";

export function FindingTable({
  findings,
  scanId,
  selectedId,
  search,
}: {
  findings: Finding[];
  scanId?: string;
  selectedId?: string;
  search?: URLSearchParams;
}) {
  const hrefFor = (finding: Finding) => {
    const params = new URLSearchParams(search?.toString());
    params.set("finding", finding.id);
    return `/app/projects/local/findings?${params.toString()}`;
  };
  return (
    <div className="app-panel">
      <div className="panel-title">
        <h2>Findings</h2>
        <span className="mono muted">{findings.length} total</span>
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
            findings.map((finding) => (
              <tr className={`interactive-row${finding.id === selectedId ? " selected-row" : ""}`} key={finding.id}>
                <td>
                  <span className={severityClass(finding.severity)}>{finding.severity}</span>
                </td>
                <td>
                  {scanId ? <a href={hrefFor(finding)}><strong>{finding.title}</strong></a> : <strong>{finding.title}</strong>}
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
    </div>
  );
}
