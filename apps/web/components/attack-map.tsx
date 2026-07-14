import type { Scan } from "@/lib/types";

export function AttackMapPanel({ scan }: { scan: Scan }) {
  const nodes = scan.code_graph.nodes.length ? scan.code_graph.nodes : [];
  return (
    <div className="attack-canvas" aria-label="Attack map">
      {nodes.slice(0, 8).map((node, index) => (
        <div
          className="attack-node"
          key={node.id}
          style={{ left: 24 + (index % 3) * 230, top: 24 + Math.floor(index / 3) * 128 }}
        >
          <span className="mono muted">{node.kind}</span>
          <strong style={{ display: "block", marginTop: 8 }}>{node.label}</strong>
          {node.risk ? <p style={{ color: `var(--${node.risk})` }}>Risk: {node.risk}</p> : null}
        </div>
      ))}
    </div>
  );
}
