import { ScanLauncher } from "@/components/scan-launcher";
import { getScans } from "@/lib/nope-data";

export default async function ScansPage() {
  const scans = await getScans();
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Scans</p>
          <h1>Run the thing that tells you no.</h1>
          <p>Repository, URL, and full scans keep deterministic evidence separate from optional AI reasoning.</p>
        </div>
      </section>
      <div className="app-grid split">
        <div className="app-panel">
          <div className="panel-title"><h2>Start scan</h2><span className="mono muted">authorized scope required</span></div>
          <ScanLauncher />
        </div>
        <div className="app-panel">
          <div className="panel-title"><h2>History</h2><span className="mono muted">{scans.length} scans</span></div>
          <table className="table">
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}><td className="mono">{scan.id}</td><td>{scan.status}</td><td>{scan.verdict}</td></tr>
              ))}
              {scans.length === 0 ? <tr><td>No scans yet.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
