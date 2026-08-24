import Link from "next/link";
import { ArrowRight, CheckCircle2, CircleAlert, FileSearch, Gauge, Radar, ScanSearch, SearchCode, ShieldCheck } from "lucide-react";
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
  const needsReview = findings.filter((finding) => !finding.disposition?.startsWith("confirmed"));
  const urgent = findings.filter((finding) => ["critical", "high"].includes(finding.severity));
  const coverage = scan.coverage ?? [];
  const scannerRuns = scan.scanner_runs ?? [];
  const gaps = coverage.filter((record) => record.status === "Not tested" || record.status === "Failed");
  const hasScan = scan.id !== "fresh_workspace";
  const scanQuery = hasScan ? `?scan=${encodeURIComponent(scan.id)}` : "";
  const projectScanHref = activeProject ? `/app/projects/local/scans/${activeProject.id}` : "/app/projects/local/scans";
  const nextHref = !activeProject ? "/app/projects/local/scans" : !hasScan ? projectScanHref : urgent.length ? `/app/projects/local/findings${scanQuery}` : needsReview.length ? `/app/projects/local/investigations${scanQuery}` : projectScanHref;
  const nextLabel = !activeProject ? "Create your first project" : !hasScan ? "Upload a repository" : urgent.length ? `Review ${urgent.length} high-impact finding${urgent.length === 1 ? "" : "s"}` : needsReview.length ? `Investigate ${needsReview.length} uncertain signal${needsReview.length === 1 ? "" : "s"}` : "Run another scan";

  return (
    <div className="overview-command-center">
      <section className="command-hero">
        <div className="command-hero-copy">
          <p className="section-kicker">Security workspace</p>
          <h1>{activeProject ? activeProject.name : "Start with one application"}<span className="wordmark-dot">.</span></h1>
          <p>{hasScan ? "NOPE has reduced the scanner noise into the signals that deserve your attention." : "Upload an application. NOPE will find what is worth your attention, show the evidence, and help you verify the fix."}</p>
          <div className="command-actions">
            <Link className="button primary command-primary-action" href={nextHref}>{nextLabel}<ArrowRight size={17} /></Link>
            {hasScan ? <Link className="button ghost" href={`/app/projects/local/findings${scanQuery}`}>View all findings</Link> : null}
          </div>
        </div>
        <div className={`trust-orbit${hasScan ? "" : " is-idle"}`}>
          <div className="trust-orbit-ring" aria-hidden="true" />
          <div className="trust-orbit-core"><ShieldCheck size={28} /><strong>{hasScan ? scan.score : "—"}</strong><span>trust score</span></div>
          <span className="orbit-label orbit-label-top">{scan.status}</span>
          <span className="orbit-label orbit-label-bottom">{scan.coverage_percent}% covered</span>
        </div>
      </section>

      <section className="attention-strip" aria-label="Current security summary">
        <SummaryMetric icon={<CircleAlert size={18} />} label="Needs attention" value={urgent.length} note="critical + high" tone="hot" />
        <SummaryMetric icon={<CheckCircle2 size={18} />} label="Confirmed" value={confirmed.length} note="evidence-backed" />
        <SummaryMetric icon={<FileSearch size={18} />} label="Needs review" value={needsReview.length} note="uncertain, not hidden" />
        <SummaryMetric icon={<Gauge size={18} />} label="Coverage gaps" value={gaps.length} note={gaps.length ? "failed or untested" : "all checked"} />
      </section>

      <section className="overview-main-grid">
        <div className="app-panel next-step-panel">
          <div className="panel-title"><div><p className="detail-eyebrow">Recommended next step</p><h2>{nextLabel}</h2></div><span className="step-badge">01</span></div>
          <p className="muted">{!hasScan ? "A scan creates the evidence NOPE needs. Nothing is guessed before that." : urgent.length ? "Start with the highest-impact retained signals. Each one includes its source, location, disposition, and evidence." : needsReview.length ? "These signals are intentionally uncertain. Investigate them without changing their deterministic classification." : "No urgent retained signals remain in this scan. Rescan after changes to measure drift."}</p>
          <Link className="next-step-link" href={nextHref}>Continue workflow <ArrowRight size={16} /></Link>
        </div>

        <div className="app-panel scan-context-panel">
          <div className="panel-title"><h2>Current scan</h2><span className={`status-light ${scan.status}`} /> </div>
          <dl className="compact-scan-context">
            <div><dt>Repository</dt><dd>{scan.repository_name ?? "No upload yet"}</dd></div>
            <div><dt>Status</dt><dd>{scan.status}</dd></div>
            <div><dt>Scanners</dt><dd>{scannerRuns.filter((run) => run.status === "passed").length}/{scannerRuns.length} passed</dd></div>
            <div><dt>Drift</dt><dd>{comparison ? `${comparison.summary.new ?? 0} new · ${comparison.summary.fixed ?? 0} fixed` : "Needs two scans"}</dd></div>
          </dl>
        </div>
      </section>

      <section className="analysis-hub">
        <div className="analysis-hub-heading"><div><p className="section-kicker">Go deeper</p><h2>Analyze this scan</h2></div><p>Open these only when you need supporting context.</p></div>
        <div className="analysis-card-grid">
          <AnalysisCard href={`/app/projects/local/coverage${scanQuery}`} icon={<Gauge />} title="Coverage" copy="See what ran, failed, or was not tested." meta={`${scan.coverage_percent}%`} />
          <AnalysisCard href={`/app/projects/local/attack-map${scanQuery}`} icon={<Radar />} title="Attack map" copy="Trace routes, handlers, and exposed paths." meta={`${scan.code_graph?.nodes?.length ?? 0} nodes`} />
          <AnalysisCard href={`/app/projects/local/search${scanQuery}`} icon={<SearchCode />} title="Repository search" copy="Retrieve focused code and security context." meta="hybrid RAG" />
          <AnalysisCard href={projectScanHref} icon={<ScanSearch />} title="Scan history" copy="Compare runs, baselines, and security drift." meta={`${scans.length} runs`} />
        </div>
      </section>
    </div>
  );
}

function SummaryMetric({ icon, label, value, note, tone = "" }: { icon: React.ReactNode; label: string; value: number; note: string; tone?: string }) {
  return <div className={`attention-metric ${tone}`}><span className="attention-icon">{icon}</span><span><small>{label}</small><strong>{value}</strong><em>{note}</em></span></div>;
}

function AnalysisCard({ href, icon, title, copy, meta }: { href: string; icon: React.ReactNode; title: string; copy: string; meta: string }) {
  return <Link className="analysis-card" href={href}><span className="analysis-card-icon">{icon}</span><span><strong>{title}</strong><small>{copy}</small></span><em>{meta}</em><ArrowRight className="analysis-card-arrow" size={16} /></Link>;
}
