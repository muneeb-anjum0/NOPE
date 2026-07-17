import type { Scan } from "@/lib/types";

type GraphNode = Scan["code_graph"]["nodes"][number];
type GraphEdge = NonNullable<Scan["code_graph"]["edges"]>[number];
type PositionedNode = GraphNode & {
  x: number;
  y: number;
  width: number;
  height: number;
};

const NODE_WIDTH = 230;
const NODE_HEIGHT = 92;
const COLUMN_X: Record<string, number> = {
  "entry point": 52,
  file: 350,
  login: 350,
  authorization: 646,
  database: 646,
};

function nodeColumn(node: GraphNode, index: number) {
  return COLUMN_X[node.kind] ?? 52 + (index % 3) * 298;
}

function positionNodes(nodes: GraphNode[]) {
  const counts = new Map<string, number>();
  return nodes.slice(0, 18).map((node, index): PositionedNode => {
    const group = node.kind;
    const seen = counts.get(group) ?? 0;
    counts.set(group, seen + 1);
    return {
      ...node,
      x: nodeColumn(node, index),
      y: 52 + seen * 132,
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    };
  });
}

function edgePath(source: PositionedNode, target: PositionedNode) {
  const startX = source.x + source.width;
  const startY = source.y + source.height / 2;
  const endX = target.x;
  const endY = target.y + target.height / 2;
  const midX = startX + Math.max(48, (endX - startX) / 2);
  return `M ${startX} ${startY} H ${midX} V ${endY} H ${endX}`;
}

export function AttackMapPanel({ scan }: { scan: Scan }) {
  const graph = scan.code_graph ?? { nodes: [], edges: [] };
  const positioned = positionNodes(graph.nodes ?? []);
  const nodeById = new Map(positioned.map((node) => [node.id, node]));
  const edges = (graph.edges ?? []).filter((edge) => nodeById.has(edge.source) && nodeById.has(edge.target));

  if (!positioned.length) {
    return (
      <div className="attack-canvas attack-canvas-empty" aria-label="Attack map empty state">
        <div>
          <span className="mono muted">No attack map yet</span>
          <strong>Run a repository or full ZIP scan with route files.</strong>
          <p>
            The map is generated during the scan stage named Building attack surface. It appears when NOPE finds
            routes such as Next.js app/api route files, pages/api files, Express/FastAPI route declarations, and
            related database or authorization signals.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="attack-canvas" aria-label="Attack map">
      <svg className="attack-edges" viewBox="0 0 980 520" preserveAspectRatio="none" aria-hidden="true">
        {edges.map((edge: GraphEdge) => {
          const source = nodeById.get(edge.source);
          const target = nodeById.get(edge.target);
          if (!source || !target) return null;
          return (
            <g key={`${edge.source}-${edge.relationship}-${edge.target}`}>
              <path d={edgePath(source, target)} />
              <text x={(source.x + target.x + source.width) / 2} y={(source.y + target.y + NODE_HEIGHT) / 2 - 8}>
                {edge.relationship}
              </text>
            </g>
          );
        })}
      </svg>
      {positioned.map((node) => (
        <div
          className={`attack-node attack-node-${node.kind.replaceAll(" ", "-")}`}
          key={node.id}
          style={{ left: node.x, top: node.y, width: node.width, minHeight: node.height }}
        >
          <span className="mono muted">{node.kind}</span>
          <strong>{node.label}</strong>
          {node.risk ? <p>Risk: {node.risk}</p> : null}
        </div>
      ))}
    </div>
  );
}
