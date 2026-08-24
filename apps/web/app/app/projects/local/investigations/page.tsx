import Link from "next/link";
import { AIFindingActions } from "@/components/ai-finding-actions";
import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { freshScan, getFindingObservations, getProjects, getScans, selectScan, severityClass } from "@/lib/nope-data";

type PageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

function paramsFrom(input: Record<string, string | string[] | undefined>) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(input)) {
    if (Array.isArray(value)) value.forEach((entry) => params.append(key, entry));
    else if (value) params.set(key, value);
  }
  return params;
}

export default async function InvestigationsPage({ searchParams }: PageProps) {
  const params = paramsFrom((await searchParams) ?? {});
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.get("scan")) ?? freshScan();
  const results = (await getFindingObservations(scan.id, "raw")) ?? {
    scan_id: scan.id,
    total: (scan.raw_observations ?? scan.findings).length,
    page: 1,
    page_size: 12,
    pages: 1,
    sort: "severity",
    direction: "asc" as const,
    filters: {},
    items: scan.raw_observations ?? scan.findings,
  };
  const selected = results.items.find((finding) => finding.id === params.get("finding")) ?? results.items[0] ?? null;

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Investigate</p>
          <h1><PinkDotText text="Turn a signal into a decision." /></h1>
          <p>{activeProject ? `Challenge the evidence, understand reachability, and plan a verified fix for ${activeProject.name}.` : "Choose an active project to investigate findings."}</p>
        </div>
      </section>

      {!selected ? (
        <div className="app-panel">
          <div className="panel-title"><h2>No findings to investigate</h2></div>
          <p className="muted">Run a scan first. Confirmed, conditional, informational, and withheld findings will appear here.</p>
        </div>
      ) : (
        <div className="investigation-page-grid">
          <aside className="app-panel investigation-secondary">
            <div className="panel-title">
              <div><p className="detail-eyebrow">Queue</p><h2>Choose a finding</h2></div>
              <span className="mono">{results.total}</span>
            </div>
            <nav className="investigation-picker" aria-label="Investigation findings">
              {results.items.map((finding, index) => {
                const next = new URLSearchParams(params.toString());
                next.set("scan", scan.id);
                next.set("finding", finding.id);
                return (
                  <Link className={finding.id === selected.id ? "is-active" : ""} href={`/app/projects/local/investigations?${next.toString()}`} key={finding.id}>
                    <span className="mono">{String(index + 1).padStart(2, "0")}</span>
                    <span><strong>{finding.title}</strong><small>{finding.severity} · {finding.disposition ?? "confirmed"}</small></span>
                  </Link>
                );
              })}
            </nav>
          </aside>
          <section className="app-panel investigation-primary">
            <div className="panel-title">
              <div>
                <p className="detail-eyebrow">Selected finding</p>
                <h2>{selected.title}</h2>
              </div>
              <span className={severityClass(selected.severity)}>{selected.severity}</span>
            </div>
            <p className="muted">{selected.description}</p>
            <dl className="detail-grid">
              <div><dt>Location</dt><dd className="mono">{selected.affected_file ?? selected.affected_route ?? "n/a"}</dd></div>
              <div><dt>Confidence</dt><dd>{selected.confidence}</dd></div>
              <div><dt>Disposition</dt><dd>{selected.disposition ?? "confirmed"}</dd></div>
              <div><dt>Rule</dt><dd>{selected.nope_rule_id ?? selected.original_rule_id ?? "n/a"}</dd></div>
              <div><dt>Sources</dt><dd>{selected.scanner_sources.join(" + ") || "n/a"}</dd></div>
            </dl>
            <AIFindingActions finding={selected} scanId={scan.id} showInvestigationControls />
          </section>
        </div>
      )}
    </>
  );
}
