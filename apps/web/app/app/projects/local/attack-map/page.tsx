import { AttackMapPanel } from "@/components/attack-map";
import { PinkDotText } from "@/components/pink-dot-text";
import { freshScan, getScans, selectScan } from "@/lib/nope-data";

export default async function AttackMapPage({
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
          <p className="section-kicker">Attack Map</p>
          <h1><PinkDotText text="Where input meets sensitive data." /></h1>
          <p>NOPE connects routes, handlers, files, databases, authorization hints, and risky paths.</p>
        </div>
      </section>
      <div className="app-panel">
        <AttackMapPanel scan={scan} />
      </div>
    </>
  );
}
