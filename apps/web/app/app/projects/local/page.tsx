import Link from "next/link";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { freshScan, getFindingObservations, getProjects, getScanComparison, getScans, selectScan } from "@/lib/nope-data";
import { scansAreComparable } from "@/lib/scan-identity";

export default async function ProjectOverview({ searchParams }: { searchParams?: Promise<{ scan?: string }> }) {
  const params = (await searchParams) ?? {};
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.scan) ?? freshScan();
  const scanIndex = scans.findIndex((item) => item.id === scan.id);
  const previous = scans.find((item, index) => index > scanIndex && scansAreComparable(scan, item));
  const [comparison, observations] = await Promise.all([
    previous ? getScanComparison(scan.id, previous.id) : Promise.resolve(null),
    scan.id !== "fresh_workspace" ? getFindingObservations(scan.id, "raw") : Promise.resolve(null),
  ]);
  const findings = (observations?.items ?? scan.raw_observations ?? scan.findings).filter((finding) => finding.disposition !== "rejected");
  const confirmed = findings.filter((finding) => finding.disposition?.startsWith("confirmed"));
  const review = findings.filter((finding) => !finding.disposition?.startsWith("confirmed"));
  const urgent = findings.filter((finding) => ["critical", "high"].includes(finding.severity));
  const gaps = (scan.coverage ?? []).filter((record) => record.status === "Not tested" || record.status === "Failed");
  const hasScan = scan.id !== "fresh_workspace";
  const scanQuery = hasScan ? `?scan=${encodeURIComponent(scan.id)}` : "";
  const scanHref = activeProject ? `/app/projects/local/scans/${activeProject.id}` : "/app/projects/local/scans";
  const nextHref = !hasScan ? scanHref : urgent.length ? `/app/projects/local/findings${scanQuery}` : review.length ? `/app/projects/local/investigations${scanQuery}` : scanHref;
  const nextLabel = !hasScan ? "Upload repository" : urgent.length ? `Review ${urgent.length} high-impact findings` : review.length ? `Investigate ${review.length} signals` : "Run another scan";

  return (
    <div className="minimal-overview">
      <header className="minimal-overview-header">
        <div>
          <p className="section-kicker">Overview</p>
          <h1>{activeProject?.name ?? "No project selected"}</h1>
          <p>{hasScan ? `${scan.repository_name ?? "Repository"} · ${scan.status}` : "Upload a repository to begin."}</p>
        </div>
        <div className="minimal-overview-actions">
          <Link className="button primary" href={nextHref}>{nextLabel}</Link>
          {hasScan ? <Link className="button ghost" href={`/app/projects/local/findings${scanQuery}`}>All findings</Link> : null}
        </div>
      </header>

      <section className="minimal-stat-row" aria-label="Current scan summary">
        <Stat label="Score" value={hasScan ? scan.score : "—"} />
        <Stat label="High impact" value={urgent.length} />
        <Stat label="Confirmed" value={confirmed.length} />
        <Stat label="Review" value={review.length} />
        <Stat label="Coverage gaps" value={gaps.length} />
      </section>

      <section className="minimal-overview-body">
        <div className="minimal-next-step">
          <span className="mono muted">Next</span>
          <h2>{nextLabel}</h2>
          <p>{!hasScan ? "NOPE needs scan evidence before it can make a useful assessment." : urgent.length ? "Start with retained critical and high-severity signals." : review.length ? "Resolve the remaining uncertainty without changing deterministic evidence." : "Rescan after changes to measure drift."}</p>
          <Link href={nextHref}>Continue</Link>
        </div>
        <dl className="minimal-scan-facts">
          <div><dt>Repository</dt><dd>{scan.repository_name ?? "—"}</dd></div>
          <div><dt>Coverage</dt><dd>{scan.coverage_percent}%</dd></div>
          <div><dt>Scanners</dt><dd>{(scan.scanner_runs ?? []).filter((run) => run.status === "passed").length}/{(scan.scanner_runs ?? []).length} passed</dd></div>
          <div><dt>Drift</dt><dd>{comparison ? `${comparison.summary.new ?? 0} new · ${comparison.summary.fixed ?? 0} fixed` : "Needs two scans"}</dd></div>
        </dl>
      </section>

      <nav className="minimal-analysis-links" aria-label="Scan analysis">
        <span>More</span>
        <Link href={`/app/projects/local/coverage${scanQuery}`}>Coverage</Link>
        <Link href={`/app/projects/local/attack-map${scanQuery}`}>Attack map</Link>
        <Link href={`/app/projects/local/search${scanQuery}`}>Repository search</Link>
        <Link href={scanHref}>Scan history</Link>
      </nav>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}
