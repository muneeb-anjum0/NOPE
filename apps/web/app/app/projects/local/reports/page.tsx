import Link from "next/link";
import { PinkDotText } from "@/components/pink-dot-text";
import { PUBLIC_API_BASE } from "@/lib/api";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { getProjects, getScans } from "@/lib/nope-data";
import type { Scan } from "@/lib/types";

const reportFormats = [
  ["PDF", "review packet", "pdf"],
  ["MD", "engineer handoff", "md"],
  ["JSON", "automation", "json"],
  ["SARIF", "code scanning", "sarif"],
] as const;

function formatScanTime(scan: Scan) {
  const value = scan.completed_at ?? scan.started_at;
  if (!value) return "time unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function reportName(scan: Scan, index: number) {
  if (scan.repository_name && scan.repository_name !== "Uploaded ZIP") return scan.repository_name;
  return `Scan ${index + 1}`;
}

function severitySummary(scan: Scan) {
  const counts = scan.findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
    return acc;
  }, {});
  return ["critical", "high", "medium", "low", "info"]
    .filter((severity) => counts[severity])
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(" / ") || "no findings";
}

function ReportCell({ scan, name, detail, format }: { scan: Scan; name: string; detail: string; format: string }) {
  return (
    <a className="report-format-cell" href={`${PUBLIC_API_BASE}/api/scans/${scan.id}/report.${format}`}>
      <strong>{name}</strong>
      <span>{detail}</span>
    </a>
  );
}

function ReportRow({ scan, index }: { scan: Scan; index: number }) {
  return (
    <article className="report-board-row">
      <div className="report-scan-stamp">
        <span className="mono muted">{formatScanTime(scan)}</span>
        <strong>{reportName(scan, index)}</strong>
        <small>{scan.id}</small>
      </div>
      <div className="report-scan-context">
        <span>{scan.status}</span>
        <span>{scan.mode}</span>
        <span>{scan.coverage_percent}% coverage</span>
        <span>{scan.scanner_runs.length} scanner runs</span>
        <span>{severitySummary(scan)}</span>
      </div>
      <div className="report-format-grid">
        {reportFormats.map(([name, detail, format]) => (
          <ReportCell detail={detail} format={format} key={format} name={name} scan={scan} />
        ))}
      </div>
    </article>
  );
}

export default async function ReportsPage() {
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const scans = scansForProject(allScans, activeProjectId);

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Reports</p>
          <h1><PinkDotText text="Export board." /></h1>
          <p>
            {activeProject
              ? `${activeProject.name}: every scan in this folder, every export format, one compact board.`
              : "Create or open a scan folder to export reports."}
          </p>
        </div>
        {activeProject ? (
          <Link className="button ghost" href={`/app/projects/local/scans/${encodeURIComponent(activeProject.id)}`}>
            Open folder
          </Link>
        ) : null}
      </section>

      {scans.length ? (
        <section className="report-board">
          <div className="report-board-header">
            <span>Scan</span>
            <span>Context</span>
            <span>Exports</span>
          </div>
          <div className="report-board-rows">
            {scans.map((scan, index) => <ReportRow index={index} key={scan.id} scan={scan} />)}
          </div>
        </section>
      ) : (
        <div className="app-panel">
          <div className="panel-title">
            <h2>No reports yet</h2>
            <span className="mono muted">folder empty</span>
          </div>
          <p className="muted">Run a scan inside this folder first. Reports are generated from scan evidence.</p>
        </div>
      )}
    </>
  );
}
