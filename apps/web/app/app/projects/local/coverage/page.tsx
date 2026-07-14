import { freshScan, getLatestScan } from "@/lib/nope-data";

export default async function CoveragePage() {
  const scan = (await getLatestScan()) ?? freshScan();
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Coverage</p>
          <h1>Not tested does not mean secure.</h1>
          <p>Scanner failures and untested domains are first-class evidence.</p>
        </div>
      </section>
      <div className="app-panel">
        <table className="table">
          <thead>
            <tr><th>Domain</th><th>Status</th><th>Scanners</th><th>Notes</th></tr>
          </thead>
          <tbody>
            {scan.coverage.map((record) => (
              <tr key={record.domain}>
                <td><strong>{record.domain}</strong></td>
                <td>{record.status}</td>
                <td className="mono">{record.scanners.join(", ") || "none"}</td>
                <td className="muted">{record.notes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
