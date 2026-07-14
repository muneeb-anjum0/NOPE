import { AttackMapPanel } from "@/components/attack-map";
import { FindingTable } from "@/components/finding-table";
import { ScanLauncher } from "@/components/scan-launcher";
import { SeveritySummary } from "@/components/summary";
import { demoScan, getLatestScan } from "@/lib/nope-data";

export default async function ProjectOverview() {
  const scan = (await getLatestScan()) ?? demoScan();
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
              <h2>Launch scan</h2>
              <span className="mono muted">local demo</span>
            </div>
            <ScanLauncher />
          </div>
          <div className="app-panel">
            <h2>AI review</h2>
            <p className="muted">{scan.ai_review.message}</p>
            <span className="severity-pill severity-low">{scan.ai_review.status}</span>
          </div>
        </div>
      </section>
    </>
  );
}
