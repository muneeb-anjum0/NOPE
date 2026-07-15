import { FindingTable } from "@/components/finding-table";
import { AIFindingActions } from "@/components/ai-finding-actions";
import { freshScan, getLatestScan } from "@/lib/nope-data";

export default async function FindingsPage() {
  const scan = (await getLatestScan()) ?? freshScan();
  const first = scan.findings[0];
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Findings</p>
          <h1>Evidence, not vibes.</h1>
          <p>Filter, inspect, explain, fix, test, and rescan. Serious findings stay serious.</p>
        </div>
      </section>
      <div className="app-grid split">
        <FindingTable findings={scan.findings} />
        <div className="app-panel">
          <div className="panel-title">
            <h2>Finding detail</h2>
            <span className="mono muted">Overview / Evidence / Fix / Tests</span>
          </div>
          {first ? (
            <>
              <span className={`severity-pill severity-${first.severity}`}>{first.severity}</span>
              <h2>{first.title}</h2>
              <p className="muted">{first.remediation}</p>
              <AIFindingActions finding={first} />
            </>
          ) : (
            <p className="muted">Run a scan to inspect finding evidence.</p>
          )}
        </div>
      </div>
    </>
  );
}
