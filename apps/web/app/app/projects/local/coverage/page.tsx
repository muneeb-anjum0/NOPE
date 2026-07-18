import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { freshScan, getProjects, getScans, selectScan } from "@/lib/nope-data";
import type { CoverageRecord } from "@/lib/types";

const STATUS_ORDER = ["Verified", "Partial", "Failed", "Not tested", "Not applicable"];

function statusClass(status: string) {
  if (status === "Verified") return "is-verified";
  if (status === "Failed") return "is-failed";
  if (status === "Partial") return "is-partial";
  if (status === "Not applicable") return "is-muted";
  return "is-untested";
}

function groupCoverage(records: CoverageRecord[]) {
  return STATUS_ORDER.map((status) => ({
    status,
    records: records.filter((record) => record.status === status),
  })).filter((group) => group.records.length);
}

function CoverageMetric({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className={`coverage-metric ${tone ?? ""}`}>
      <span className="mono muted">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function CoverageCard({ record }: { record: CoverageRecord }) {
  return (
    <article className={`coverage-domain-card ${statusClass(record.status)}`}>
      <div>
        <strong>{record.domain}</strong>
        <span>{record.status}</span>
      </div>
      <p>{record.notes}</p>
      <div className="coverage-scanner-tags">
        {record.scanners.length ? record.scanners.map((scanner) => <span key={scanner}>{scanner}</span>) : <span>no scanner</span>}
      </div>
    </article>
  );
}

export default async function CoveragePage({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.scan) ?? freshScan();
  const coverage = scan.coverage ?? [];
  const verified = coverage.filter((record) => record.status === "Verified").length;
  const failed = coverage.filter((record) => record.status === "Failed").length;
  const untested = coverage.filter((record) => record.status === "Not tested").length;
  const partial = coverage.filter((record) => record.status === "Partial").length;
  const groups = groupCoverage(coverage);
  const dynamicRecords = coverage.filter((record) => record.domain === "Dynamic testing" || record.domain === "URL scanning");
  const dynamicRuns = (scan.scanner_runs ?? []).filter((run) => ["OWASP ZAP", "NOPE URL scanner", "NOPE sandbox"].includes(run.scanner));

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Coverage</p>
          <h1><PinkDotText text="Not tested does not mean secure." /></h1>
          <p>Scanner failures and untested domains are first-class evidence.</p>
        </div>
      </section>
      <section className="coverage-command">
        <div className="coverage-command-strip">
          <CoverageMetric label="Verified" tone="is-verified" value={verified} />
          <CoverageMetric label="Partial" tone="is-partial" value={partial} />
          <CoverageMetric label="Failed" tone="is-failed" value={failed} />
          <CoverageMetric label="Not tested" tone="is-untested" value={untested} />
        </div>
        <div className="dynamic-coverage-strip">
          <span className="mono">dynamic</span>
          {dynamicRecords.length ? dynamicRecords.map((record) => (
            <span key={record.domain}>{record.domain}: {record.status}</span>
          )) : <span>No dynamic coverage recorded</span>}
          {dynamicRuns.length ? dynamicRuns.map((run) => (
            <span key={`${run.scanner}-${run.status}`}>{run.scanner}: {run.status}</span>
          )) : null}
        </div>
        <div className="coverage-lane-board">
          {groups.map((group) => (
            <section className={`coverage-lane ${statusClass(group.status)}`} key={group.status}>
              <div className="coverage-lane-title">
                <h2>{group.status}</h2>
                <span className="mono muted">{group.records.length}</span>
              </div>
              <div className="coverage-domain-list">
                {group.records.map((record) => <CoverageCard key={record.domain} record={record} />)}
              </div>
            </section>
          ))}
        </div>
      </section>
    </>
  );
}
