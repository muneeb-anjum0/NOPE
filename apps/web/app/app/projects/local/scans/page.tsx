import { ScanLauncher } from "@/components/scan-launcher";
import { PinkDotText } from "@/components/pink-dot-text";
import { getBaselines, getScanComparison, getScans, selectScan } from "@/lib/nope-data";

export default async function ScansPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; scan?: string }>;
}) {
  const params = await searchParams;
  const scans = await getScans();
  const selected = selectScan(scans, params.scan);
  const selectedIndex = selected ? scans.findIndex((scan) => scan.id === selected.id) : -1;
  const previous = selected ? scans.find((scan, index) => index > selectedIndex && (!selected.project_id || scan.project_id === selected.project_id)) : null;
  const comparison = selected && previous ? await getScanComparison(selected.id, previous.id) : null;
  const baselines = await getBaselines(selected?.project_id ?? null);
  const labelFor = (scan: NonNullable<typeof selected>, index: number) => {
    if (scan.repository_name && scan.repository_name !== "Uploaded ZIP") return scan.repository_name;
    return scan.id || `Upload ${index + 1}`;
  };
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Scans</p>
          <h1><PinkDotText text="Run the thing that tells you no." /></h1>
          <p>Repository, URL, and full scans keep deterministic evidence separate from optional AI reasoning.</p>
        </div>
      </section>
      <div className="app-grid split">
        <div className="app-panel">
          <div className="panel-title"><h2>Start scan</h2><span className="mono muted">authorized scope required</span></div>
          {params.error ? <p className="login-error">{params.error}</p> : null}
          <ScanLauncher />
        </div>
        <div className="app-panel">
          <div className="panel-title"><h2>History</h2><span className="mono muted">{scans.length} scans</span></div>
          <table className="table">
            <tbody>
              {scans.map((scan) => (
                <tr className={scan.id === selected?.id ? "selected-row" : ""} key={scan.id}>
                  <td><a className="mono" href={`/app/projects/local/scans?scan=${encodeURIComponent(scan.id)}`}>{labelFor(scan, scans.indexOf(scan))}</a></td>
                  <td>{scan.status}</td>
                  <td>{scan.verdict}</td>
                  <td>
                    <form action="/api/delete-scan" method="post">
                      <input name="scanId" type="hidden" value={scan.id} />
                      <button className="button ghost danger-button" type="submit">Delete</button>
                    </form>
                  </td>
                </tr>
              ))}
              {scans.length === 0 ? <tr><td>No scans yet.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>
      <section className="app-grid split">
        <div className="app-panel">
          <div className="panel-title"><h2>Latest drift</h2><span className="mono muted">{comparison ? `${comparison.current_scan_id} vs ${comparison.reference_scan_id}` : "needs two scans"}</span></div>
          {comparison ? (
            <>
              <div className="metric-grid">
                <Metric label="New" value={comparison.summary.new ?? 0} />
                <Metric label="Fixed" value={comparison.summary.fixed ?? 0} />
                <Metric label="Reintroduced" value={comparison.summary.reintroduced ?? 0} />
                <Metric label="Coverage drift" value={comparison.summary.coverage_drift ?? 0} />
              </div>
              <div className="detail-stack">
                {comparison.drift_events.slice(0, 5).map((event, index) => (
                  <div className="collapse-row" key={`${event.type}-${index}`}>
                    <strong>{event.type.replaceAll("_", " ")}</strong>
                    <span className="muted">{event.message}</span>
                    <span className="severity-pill severity-info">{event.severity ?? "info"}</span>
                  </div>
                ))}
                {comparison.drift_events.length === 0 ? <p className="muted">No drift detected between the latest two scans.</p> : null}
              </div>
            </>
          ) : (
            <p className="muted">Run at least two scans to compare latest vs previous.</p>
          )}
        </div>
        <div className="app-panel">
          <div className="panel-title"><h2>Baselines</h2><span className="mono muted">{baselines.length} saved</span></div>
          <div className="detail-stack">
            {baselines.map((baseline) => (
              <div className="collapse-row" key={baseline.id}>
                <strong>{baseline.name}</strong>
                <span className="mono muted">{baseline.scan_id ?? "scan unknown"}</span>
                <span className="severity-pill severity-info">{new Date(baseline.created_at).toLocaleDateString()}</span>
              </div>
            ))}
            {baselines.length === 0 ? <p className="muted">Create a baseline from a scan to track new, fixed, and reintroduced risk.</p> : null}
          </div>
          {comparison ? (
            <div className="evidence-card">
              <strong>Incremental scope</strong>
              <p className="muted">{comparison.incremental_scope.note}</p>
              <p className="mono">{(comparison.incremental_scope.changed_files ?? []).slice(0, 4).join(", ") || "No changed files inferred."}</p>
            </div>
          ) : null}
        </div>
      </section>
    </>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
