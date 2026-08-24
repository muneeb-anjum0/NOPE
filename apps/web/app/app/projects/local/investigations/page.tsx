import { AIFindingActions } from "@/components/ai-finding-actions";
import { FindingTable } from "@/components/finding-table";
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
          <p className="section-kicker">Investigations</p>
          <h1><PinkDotText text="Manual-review brain, deterministic spine." /></h1>
          <p>{activeProject ? `${activeProject.name}: retained findings can be investigated with bounded RAG, citations, and related evidence.` : "Choose an active folder to investigate findings."}</p>
        </div>
      </section>

      {!selected ? (
        <div className="app-panel">
          <div className="panel-title"><h2>No findings to investigate</h2></div>
          <p className="muted">Run a scan first. Confirmed, conditional, informational, and withheld findings will appear here.</p>
        </div>
      ) : (
        <div className="investigation-page-grid">
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
          <section className="app-panel investigation-secondary">
            <div className="panel-title">
              <h2>Investigation queue</h2>
              <span className="mono">{results.total} findings</span>
            </div>
            <FindingTable findings={results.items} scanId={scan.id} selectedId={selected.id} searchQuery={params.toString()} total={results.total} basePath="/app/projects/local/investigations" />
          </section>
        </div>
      )}
    </>
  );
}
