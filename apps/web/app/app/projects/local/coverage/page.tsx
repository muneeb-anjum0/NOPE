import { PinkDotText } from "@/components/pink-dot-text";
import { freshScan, getScans, selectScan } from "@/lib/nope-data";

export default async function CoveragePage({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const scans = await getScans();
  const scan = selectScan(scans, params.scan) ?? freshScan();
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Coverage</p>
          <h1><PinkDotText text="Not tested does not mean secure." /></h1>
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
