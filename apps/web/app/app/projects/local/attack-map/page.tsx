import { AttackMapPanel } from "@/components/attack-map";
import { demoScan, getLatestScan } from "@/lib/nope-data";

export default async function AttackMapPage() {
  const scan = (await getLatestScan()) ?? demoScan();
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Attack Map</p>
          <h1>Where input meets sensitive data.</h1>
          <p>NOPE connects routes, handlers, files, databases, authorization hints, and risky paths.</p>
        </div>
      </section>
      <div className="app-panel">
        <AttackMapPanel scan={scan} />
      </div>
    </>
  );
}
