import { AttackMapPanel } from "@/components/attack-map";
import { Network } from "lucide-react";
import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { freshScan, getProjects, getScans, selectScan } from "@/lib/nope-data";

export default async function AttackMapPage({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.scan) ?? freshScan();
  const nodes = scan.code_graph?.nodes ?? [];
  const edges = scan.code_graph?.edges ?? [];
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Attack Map</p>
          <h1><PinkDotText text="Understand the exposed path." /></h1>
          <p>Start with the surface summary. Open the full graph only when you need to trace a path.</p>
        </div>
      </section>
      <section className="surface-summary-grid">
        <div className="surface-summary-card"><Network size={20} /><span><strong>{nodes.length}</strong><small>mapped nodes</small></span></div>
        <div className="surface-summary-card"><Network size={20} /><span><strong>{edges.length}</strong><small>relationships</small></span></div>
        <div className="surface-summary-card"><Network size={20} /><span><strong>{nodes.filter((node) => node.kind === "entry point").length}</strong><small>entry points</small></span></div>
      </section>
      <details className="app-panel reveal-panel">
        <summary><span><strong>Open interactive attack map</strong><small>Routes, handlers, data stores, and risk paths</small></span><span className="reveal-action">Explore</span></summary>
        <div className="reveal-panel-body"><AttackMapPanel scan={scan} /></div>
      </details>
    </>
  );
}
