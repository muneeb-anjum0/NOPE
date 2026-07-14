import { demoScan, getLatestScan } from "@/lib/nope-data";

export default async function ReportsPage() {
  const scan = (await getLatestScan()) ?? demoScan();
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Reports</p>
          <h1>Evidence exports without the attitude.</h1>
          <p>Formal reports avoid sarcasm and preserve reproducibility metadata.</p>
        </div>
      </section>
      <div className="app-grid cols-3">
        {["json", "md", "sarif"].map((format) => (
          <a className="app-panel" href={`http://localhost:8000/api/scans/${scan.id}/report.${format}`} key={format}>
            <span className="mono muted">export</span>
            <h2>{format.toUpperCase()}</h2>
            <p className="muted">Download report for scan {scan.id}.</p>
          </a>
        ))}
      </div>
    </>
  );
}
