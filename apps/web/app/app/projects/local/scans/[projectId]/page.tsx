import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { ScanLauncher } from "@/components/scan-launcher";
import { ScanHistory } from "@/components/scan-history";
import { PinkDotText } from "@/components/pink-dot-text";
import { getBaselines, getProjects, getScanComparison, getScans, selectScan } from "@/lib/nope-data";
import { baselineIsComparable, scansAreComparable } from "@/lib/scan-identity";

export default async function ScanFolderPage({
  params,
  searchParams,
}: {
  params: Promise<{ projectId: string }>;
  searchParams: Promise<{ error?: string; scaffoldWarning?: string; scan?: string }>;
}) {
  const [{ projectId }, query] = await Promise.all([params, searchParams]);
  const [projects, scans] = await Promise.all([getProjects(), getScans()]);
  const project = projects.find((item) => item.id === projectId) ?? null;
  const folderScans = project ? scans.filter((scan) => scan.project_id === project.id) : [];
  const selected = project ? selectScan(folderScans, query.scan) : null;
  const selectedIndex = selected ? folderScans.findIndex((scan) => scan.id === selected.id) : -1;
  const previous = selected ? folderScans.find((scan, index) => index > selectedIndex && scansAreComparable(selected, scan)) : null;
  const comparison = selected && previous ? await getScanComparison(selected.id, previous.id) : null;
  const allBaselines = await getBaselines(project?.id ?? null);
  const baselines = selected ? allBaselines.filter((baseline) => baselineIsComparable(selected, baseline)) : [];

  if (!project) {
    return (
      <div className="app-panel">
        <div className="panel-title"><h2>Folder not found</h2></div>
        <Link className="button ghost" href="/app/projects/local/scans"><ArrowLeft size={16} /> Back to folders</Link>
      </div>
    );
  }

  return (
    <>
      <section className="page-header folder-page-header">
        <div>
          <Link className="folder-back-link" href="/app/projects/local/scans"><ArrowLeft size={15} /> Folders</Link>
          <p className="section-kicker">Scans</p>
          <h1><PinkDotText text={project.name} /></h1>
          <p>Uploads, history, baselines, and drift stay inside this folder.</p>
        </div>
      </section>

      {query.error ? <p className="login-error">{query.error}</p> : null}

      <div className="app-grid split">
        <div className="app-panel">
          <div className="panel-title">
            <h2>Upload ZIP</h2>
            <span className="mono muted">folder scoped</span>
          </div>
          <ScanLauncher projectId={project.id} scaffoldWarning={query.scaffoldWarning} />
        </div>
        <div className="app-panel">
          <div className="panel-title">
            <h2>History</h2>
            <span className="mono muted">{folderScans.length} scans</span>
          </div>
          <ScanHistory scans={folderScans} selectedId={selected?.id} projectId={project.id} />
        </div>
      </div>

      <section className="app-grid split">
        <div className="app-panel">
          <div className="panel-title"><h2>Latest drift</h2><span className="mono muted">{comparison ? `${comparison.current_scan_id} vs ${comparison.reference_scan_id}` : "needs matching folder scan"}</span></div>
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
                {comparison.drift_events.length === 0 ? <p className="muted">No drift detected between the latest two scans in this folder.</p> : null}
              </div>
            </>
          ) : (
            <p className="muted">Run this same folder again to compare drift. Other folders and loose ZIP uploads are ignored.</p>
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
            {baselines.length === 0 ? <p className="muted">No baselines saved for this folder yet.</p> : null}
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
