import { PinkDotText } from "@/components/pink-dot-text";
import { PUBLIC_API_BASE } from "@/lib/api";
import { getScans, selectScan } from "@/lib/nope-data";

const reportSections = [
  {
    title: "Executive Report",
    summary: "Readable summary for humans who need risk, evidence, and next action.",
    rows: [
      ["PDF", "Formal paginated report for review, archival, and stakeholder handoff.", "pdf"],
      ["Markdown", "Developer-friendly report with findings and remediation.", "md"],
      ["JSON", "Structured report for automation and archival.", "json"],
    ],
  },
  {
    title: "Tooling Output",
    summary: "Machine-readable exports for security platforms and CI pipelines.",
    rows: [
      ["SARIF", "Uploadable static analysis format for code scanning tools.", "sarif"],
    ],
  },
  {
    title: "Report Notes",
    summary: "What the current report does and does not prove.",
    rows: [
      ["Coverage gaps", "Untested domains stay visible instead of being hidden.", "note"],
      ["Reproducibility", "Scanner runs, commit metadata, and evidence are preserved.", "note"],
    ],
  },
];

export default async function ReportsPage({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const scans = await getScans();
  const scan = selectScan(scans, params.scan);
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Reports</p>
          <h1><PinkDotText text="Evidence exports without the attitude." /></h1>
          <p>Formal reports avoid sarcasm and preserve reproducibility metadata.</p>
        </div>
      </section>
      <div className="collapse-list">
        {reportSections.map((section, index) => (
          <details className="collapse-panel settings-accordion" name="report-sections" key={section.title} open={index === 0}>
            <summary>
              <span>
                <h2>{section.title}</h2>
                <p>{section.summary}</p>
              </span>
              <span className="mono muted">{scan ? scan.id : "no scan yet"}</span>
            </summary>
            <div className="collapse-body">
              {section.rows.map(([name, detail, format]) => (
                <div className="collapse-row" key={name}>
                  <strong>{name}</strong>
                  <span className="muted">{detail}</span>
                  {scan && format !== "note" ? (
                    <a className="button ghost" href={`${PUBLIC_API_BASE}/api/scans/${scan.id}/report.${format}`}>
                      Download {format.toUpperCase()}
                    </a>
                  ) : (
                    <span className="severity-pill severity-info">{format === "note" ? "Tracked" : "Pending"}</span>
                  )}
                </div>
              ))}
            </div>
          </details>
        ))}
      </div>
    </>
  );
}
