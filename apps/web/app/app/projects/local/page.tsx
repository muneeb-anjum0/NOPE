import { AttackMapPanel } from "@/components/attack-map";
import { FindingTable } from "@/components/finding-table";
import { PinkDotText } from "@/components/pink-dot-text";
import { freshScan, getScanComparison, getScans, selectScan } from "@/lib/nope-data";
import { scansAreComparable } from "@/lib/scan-identity";

export default async function ProjectOverview({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const scans = await getScans();
  const scan = selectScan(scans, params.scan) ?? freshScan();
  const scanIndex = scans.findIndex((item) => item.id === scan.id);
  const previous = scans.find((item, index) => index > scanIndex && scansAreComparable(scan, item));
  const comparison = previous ? await getScanComparison(scan.id, previous.id) : null;
  const severityCounts = ["critical", "high", "medium", "low"].map((severity) => ({
    severity,
    count: (scan.findings ?? []).filter((finding) => finding.severity === severity).length,
  }));
  const coverage = scan.coverage ?? [];
  const scannerRuns = scan.scanner_runs ?? [];
  const graphNodes = scan.code_graph?.nodes ?? [];
  const untested = coverage.filter((record) => record.status === "Not tested" || record.status === "Failed");
  const pipeline = [
    ["Stack", scan.stack?.length ? "completed" : "pending"],
    ["Attack surface", graphNodes.length ? "completed" : "pending"],
    ["Scanners", scannerRuns.length ? "completed" : "pending"],
    ["Qwen", scan.ai_review?.status ?? "pending"],
  ];
  const totalFindings = (scan.findings ?? []).length;
  const hasRealScan = scan.id !== "fresh_workspace";
  const activeScanTitle = hasRealScan ? scan.repository_name || "Selected upload" : "No scan";
  const activeScanMeta = hasRealScan ? scan.id : "Upload ZIP";

  return (
    <>
      <section className="dashboard-hero">
        <div>
          <p className="section-kicker">Overview</p>
          <h1><PinkDotText text={scan.verdict} /></h1>
          <div className="hero-meta-tags" aria-label="Scan target">
            <span className="mini-tag mini-tag-label">Repository</span>
            <span className="mini-tag mono">{scan.repository_name ?? "none"}</span>
            <span className="mini-tag mini-tag-label">Target</span>
            <span className="mini-tag mono">{scan.target_url ?? "none"}</span>
          </div>
        </div>
        <div className={`dashboard-context${hasRealScan ? "" : " empty"}`}>
          <div className="active-scan-tags" aria-label="Active scan">
            <span className="mini-tag mini-tag-label">Active</span>
            <span className="mini-tag mini-tag-strong">{activeScanTitle}</span>
            <span className="mini-tag mono">{activeScanMeta}</span>
            <span className="mini-tag">{hasRealScan ? scan.status : "idle"}</span>
          </div>
        </div>
      </section>

      <section className="dashboard-scoreboard" aria-label="Scan summary">
        <div>
          <span className="mono muted">Score</span>
          <strong>{scan.score}</strong>
          <span>{scan.coverage_percent}% coverage</span>
        </div>
        <div>
          <span className="mono muted">Findings</span>
          <strong>{totalFindings}</strong>
          <span>{severityCounts.map((item) => `${item.count} ${item.severity}`).join(" / ")}</span>
        </div>
        <div>
          <span className="mono muted">Drift</span>
          <strong>{comparison ? comparison.summary.total_drift_events ?? 0 : 0}</strong>
          <span>{comparison ? `${comparison.summary.new ?? 0} new / ${comparison.summary.fixed ?? 0} fixed` : "Needs two scans"}</span>
        </div>
        <div>
          <span className="mono muted">Pipeline</span>
          <strong>{scan.status}</strong>
          <span>{scannerRuns.length} scanner runs</span>
        </div>
      </section>

      <section className="dashboard-workspace">
        <div className="dashboard-primary">
          <FindingTable findings={(scan.findings ?? []).slice(0, 5)} />
          <div className="app-panel">
            <div className="panel-title">
              <h2>Attack path preview</h2>
              <span className="mono muted">route / file / data</span>
            </div>
            <AttackMapPanel scan={scan} />
          </div>
        </div>
        <aside className="dashboard-rail">
          <div className="app-panel">
            <div className="panel-title">
              <h2>Evidence status</h2>
              <span className="mono muted">{scan.status}</span>
            </div>
            <div className="status-section">
              <span className="mono muted">Pipeline</span>
              {pipeline.map(([label, status], index) => (
                <div className="pipeline-step" key={label}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{label}</strong>
                  <span className="severity-pill severity-info">{status}</span>
                </div>
              ))}
            </div>
            <div className="status-section">
              <span className="mono muted">Scanners ({scannerRuns.length})</span>
              {scannerRuns.slice(0, 5).map((run) => (
                <div className="status-item" key={`${run.scanner}-${run.status}`}>
                  <span>{run.scanner}</span>
                  <span className={`severity-pill severity-${run.status === "failed" ? "critical" : "info"}`}>{run.status}</span>
                </div>
              ))}
              {scannerRuns.length === 0 ? <p className="muted">No scanner runs yet.</p> : null}
            </div>
            <div className="status-section">
              <span className="mono muted">Qwen</span>
              <div className="status-item">
                <span>{scan.ai_review?.message ?? "Waiting for scan evidence."}</span>
                <span className="severity-pill severity-info">{scan.ai_review?.status ?? "pending"}</span>
              </div>
            </div>
            <div className="status-section">
              <span className="mono muted">Untested / failed ({untested.length})</span>
              {untested.slice(0, 5).map((record) => (
                <div className="status-item" key={record.domain}>
                  <span>{record.domain}</span>
                  <span className={`severity-pill severity-${record.status === "Failed" ? "critical" : "medium"}`}>{record.status}</span>
                </div>
              ))}
              {untested.length === 0 ? <p className="muted">Every configured coverage domain has been exercised or marked not applicable.</p> : null}
            </div>
          </div>
        </aside>
      </section>
    </>
  );
}
