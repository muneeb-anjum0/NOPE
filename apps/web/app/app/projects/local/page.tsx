import { Brain, ListChecks, Radar, TestTube2 } from "lucide-react";
import { AttackMapPanel } from "@/components/attack-map";
import { FindingTable } from "@/components/finding-table";
import { ScanLauncher } from "@/components/scan-launcher";
import { SeveritySummary } from "@/components/summary";
import { freshScan, getLatestScan, getScanComparison, getScans } from "@/lib/nope-data";

export default async function ProjectOverview() {
  const scans = await getScans();
  const scan = scans[0] ?? (await getLatestScan()) ?? freshScan();
  const previous = scans[1];
  const comparison = previous ? await getScanComparison(scan.id, previous.id) : null;
  const severityCounts = ["critical", "high", "medium", "low"].map((severity) => ({
    severity,
    count: scan.findings.filter((finding) => finding.severity === severity).length,
  }));
  const untested = scan.coverage.filter((record) => record.status === "Not tested" || record.status === "Failed");
  const pipeline = [
    ["Stack", scan.stack?.length ? "completed" : "pending"],
    ["Attack surface", scan.code_graph.nodes.length ? "completed" : "pending"],
    ["Scanners", scan.scanner_runs.length ? "completed" : "pending"],
    ["Qwen", scan.ai_review.status],
  ];
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Overview</p>
          <h1>{scan.verdict}</h1>
          <p>
            Repository: <span className="mono">{scan.repository_name ?? "not provided"}</span> / Target:{" "}
            <span className="mono">{scan.target_url ?? "not tested"}</span>
          </p>
        </div>
        <a className="button primary" href="/app/projects/local/scans">Run scan</a>
      </section>
      <section className="dashboard-band">
        <div className="app-panel verdict-panel">
          <span className="mono muted">Verdict</span>
          <h2>{scan.verdict}</h2>
          <p className="muted">NOPE keeps scanner output, evidence, coverage gaps, and optional Qwen reasoning visible instead of flattening them into a fake all-clear.</p>
        </div>
        <div className="app-grid cols-2">
          <div className="app-panel">
            <span className="mono muted">Security score</span>
            <strong className="metric-value">{scan.score}</strong>
            <p className="muted">{scan.coverage_percent}% coverage</p>
          </div>
          <div className="app-panel">
            <span className="mono muted">Drift</span>
            <strong className="metric-value">{comparison ? comparison.summary.total_drift_events ?? 0 : 0}</strong>
            <p className="muted">{comparison ? `${comparison.summary.new ?? 0} new / ${comparison.summary.fixed ?? 0} fixed` : "Needs two scans"}</p>
          </div>
        </div>
      </section>
      <SeveritySummary scan={scan} />
      <section className="app-grid split">
        <div className="app-grid">
          <FindingTable findings={scan.findings.slice(0, 5)} />
          <div className="app-panel">
            <div className="panel-title">
              <h2>Attack path preview</h2>
              <span className="mono muted">route / file / data</span>
            </div>
            <AttackMapPanel scan={scan} />
          </div>
        </div>
        <div className="app-grid">
          <div className="app-panel">
            <div className="panel-title">
              <h2><ListChecks size={16} /> Scan pipeline</h2>
              <span className="mono muted">{scan.status}</span>
            </div>
            <div className="pipeline-list">
              {pipeline.map(([label, status], index) => (
                <div className="pipeline-step" key={label}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{label}</strong>
                  <span className="severity-pill severity-info">{status}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="app-panel">
            <div className="panel-title">
              <h2><Radar size={16} /> Scanner status</h2>
              <span className="mono muted">{scan.scanner_runs.length} runs</span>
            </div>
            <div className="status-list">
              {scan.scanner_runs.slice(0, 5).map((run) => (
                <div className="status-item" key={`${run.scanner}-${run.status}`}>
                  <span>{run.scanner}</span>
                  <span className={`severity-pill severity-${run.status === "failed" ? "critical" : "info"}`}>{run.status}</span>
                </div>
              ))}
              {scan.scanner_runs.length === 0 ? <p className="muted">No scanner runs yet.</p> : null}
            </div>
          </div>
          <div className="app-panel">
            <div className="panel-title">
              <h2>Launch scan</h2>
              <span className="mono muted">local demo</span>
            </div>
            <ScanLauncher />
          </div>
          <div className="app-panel">
            <div className="panel-title">
              <h2><Brain size={16} /> Qwen status</h2>
              <span className="severity-pill severity-info">{scan.ai_review.status}</span>
            </div>
            <p className="muted">{scan.ai_review.message}</p>
          </div>
          <div className="app-panel">
            <div className="panel-title">
              <h2><TestTube2 size={16} /> Untested areas</h2>
              <span className="mono muted">{untested.length} domains</span>
            </div>
            <div className="status-list">
              {untested.slice(0, 5).map((record) => (
                <div className="status-item" key={record.domain}>
                  <span>{record.domain}</span>
                  <span className={`severity-pill severity-${record.status === "Failed" ? "critical" : "medium"}`}>{record.status}</span>
                </div>
              ))}
              {untested.length === 0 ? <p className="muted">Every configured coverage domain has been exercised or marked not applicable.</p> : null}
            </div>
          </div>
        </div>
      </section>
      <section className="app-grid cols-4">
        {severityCounts.map(({ severity, count }) => (
          <div className="app-panel" key={severity}>
            <span className="mono muted">{severity}</span>
            <strong className="metric-value" style={{ color: `var(--${severity})` }}>{count}</strong>
            <p className="muted">latest findings</p>
          </div>
        ))}
      </section>
    </>
  );
}
