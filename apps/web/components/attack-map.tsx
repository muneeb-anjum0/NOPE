import type { Scan } from "@/lib/types";

type GraphNode = Scan["code_graph"]["nodes"][number];
type GraphEdge = NonNullable<Scan["code_graph"]["edges"]>[number];
type PositionedNode = GraphNode & {
  x: number;
  y: number;
  width: number;
  height: number;
};

type Layout = {
  nodes: PositionedNode[];
  width: number;
  height: number;
};

type Anchor = {
  x: number;
  y: number;
  side: "left" | "right" | "top" | "bottom";
};

const NODE_WIDTH = 260;
const NODE_HEIGHT = 118;
const CANVAS_PADDING = 56;
const COLUMN_GAP = 78;
const ROW_GAP = 42;
const ROW_HEIGHT = NODE_HEIGHT + ROW_GAP;
const COLUMN_X: Record<string, number> = {
  "entry point": CANVAS_PADDING,
  file: CANVAS_PADDING + NODE_WIDTH + COLUMN_GAP,
  login: CANVAS_PADDING + NODE_WIDTH + COLUMN_GAP,
  authorization: CANVAS_PADDING + (NODE_WIDTH + COLUMN_GAP) * 2,
  database: CANVAS_PADDING + (NODE_WIDTH + COLUMN_GAP) * 2,
};

function nodeColumn(node: GraphNode, index: number) {
  return COLUMN_X[node.kind] ?? CANVAS_PADDING + (index % 3) * (NODE_WIDTH + COLUMN_GAP);
}

function positionNodes(nodes: GraphNode[], edges: GraphEdge[]): Layout {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const positioned = new Map<string, PositionedNode>();
  const usedRows = new Map<string, number>();

  function place(node: GraphNode, x: number, y: number) {
    if (positioned.has(node.id)) return positioned.get(node.id);
    const placed = { ...node, x, y, width: NODE_WIDTH, height: NODE_HEIGHT };
    positioned.set(node.id, placed);
    return placed;
  }

  function rowY(row: number) {
    return CANVAS_PADDING + row * ROW_HEIGHT;
  }

  const routeNodes = nodes.filter((node) => node.kind === "entry point");
  routeNodes.forEach((routeNode, row) => {
    const y = rowY(row);
    place(routeNode, COLUMN_X["entry point"], y);
    const handledFileIds = edges
      .filter((edge) => edge.source === routeNode.id && edge.relationship === "handled by")
      .map((edge) => edge.target);
    handledFileIds.forEach((fileId) => {
      const fileNode = nodeById.get(fileId);
      if (fileNode) {
        const isNewFilePlacement = !positioned.has(fileId);
        place(fileNode, COLUMN_X.file, y);
        if (isNewFilePlacement) {
          usedRows.set(fileId, row);
        }
      }
    });
  });

  const counts = new Map<string, number>();
  nodes.forEach((node, index) => {
    if (positioned.has(node.id)) return;
    const parentEdge = edges.find((edge) => edge.target === node.id && usedRows.has(edge.source));
    if (parentEdge && (node.kind === "database" || node.kind === "authorization" || node.kind === "login")) {
      const parentRow = usedRows.get(parentEdge.source) ?? 0;
      const y = rowY(parentRow);
      place(node, nodeColumn(node, index), y);
      return;
    }
    const group = node.kind || "other";
    const seen = counts.get(group) ?? 0;
    counts.set(group, seen + 1);
    const baseRow = routeNodes.length + seen;
    place(node, nodeColumn(node, index), rowY(baseRow));
  });

  const placed = Array.from(positioned.values());
  const width = Math.max(980, ...placed.map((node) => node.x + node.width + CANVAS_PADDING));
  const height = Math.max(520, ...placed.map((node) => node.y + node.height + CANVAS_PADDING));
  return { nodes: placed, width, height };
}

function anchorFor(node: PositionedNode, side: Anchor["side"]): Anchor {
  if (side === "left") return { x: node.x, y: node.y + node.height / 2, side };
  if (side === "right") return { x: node.x + node.width, y: node.y + node.height / 2, side };
  if (side === "top") return { x: node.x + node.width / 2, y: node.y, side };
  return { x: node.x + node.width / 2, y: node.y + node.height, side };
}

function anchorsForEdge(source: PositionedNode, target: PositionedNode): [Anchor, Anchor] {
  const sourceCenterY = source.y + source.height / 2;
  const targetCenterY = target.y + target.height / 2;

  if (target.x >= source.x + source.width) {
    return [anchorFor(source, "right"), anchorFor(target, "left")];
  }
  if (source.x >= target.x + target.width) {
    return [anchorFor(source, "left"), anchorFor(target, "right")];
  }
  if (targetCenterY >= sourceCenterY) {
    return [anchorFor(source, "bottom"), anchorFor(target, "top")];
  }
  return [anchorFor(source, "top"), anchorFor(target, "bottom")];
}

function edgePath(source: PositionedNode, target: PositionedNode) {
  const [start, end] = anchorsForEdge(source, target);
  if (start.side === "right" || start.side === "left") {
    const direction = start.side === "right" ? 1 : -1;
    const midX = start.x + direction * Math.max(42, Math.abs(end.x - start.x) / 2);
    return `M ${start.x} ${start.y} H ${midX} V ${end.y} H ${end.x}`;
  }
  const direction = start.side === "bottom" ? 1 : -1;
  const midY = start.y + direction * Math.max(42, Math.abs(end.y - start.y) / 2);
  return `M ${start.x} ${start.y} V ${midY} H ${end.x} V ${end.y}`;
}

function edgeLabelPoint(source: PositionedNode, target: PositionedNode) {
  const [start, end] = anchorsForEdge(source, target);
  return {
    x: (start.x + end.x) / 2,
    y: (start.y + end.y) / 2 - 8,
  };
}

function connectedSides(node: PositionedNode, edges: GraphEdge[], nodeById: Map<string, PositionedNode>) {
  const sides = new Set<Anchor["side"]>();
  edges.forEach((edge) => {
    const source = nodeById.get(edge.source);
    const target = nodeById.get(edge.target);
    if (!source || !target) return;
    const [start, end] = anchorsForEdge(source, target);
    if (node.id === source.id) sides.add(start.side);
    if (node.id === target.id) sides.add(end.side);
  });
  return sides;
}

function AnchorDots({ connected }: { connected: Set<Anchor["side"]> }) {
  return (
    <>
      {(["top", "right", "bottom", "left"] as const).map((side) => (
        <span
          aria-hidden="true"
          className={`attack-anchor attack-anchor-${side}${connected.has(side) ? " is-connected" : ""}`}
          key={side}
        />
      ))}
    </>
  );
}

function nodeStyle(node: PositionedNode) {
  return {
    left: node.x,
    top: node.y,
    width: node.width,
    height: node.height,
  };
}

function canvasStyle(layout: Layout) {
  return {
    height: Math.min(Math.max(layout.height, 560), 860),
  };
}

function sortedEdges(edges: GraphEdge[]) {
  return edges.slice().sort((a, b) => {
    const aKey = `${a.source}:${a.target}:${a.relationship}`;
    const bKey = `${b.source}:${b.target}:${b.relationship}`;
    return aKey.localeCompare(bKey);
  });
}

function positionedNodeClass(node: PositionedNode) {
  return `attack-node attack-node-${node.kind.replaceAll(" ", "-")}`;
}

function edgeKey(edge: GraphEdge) {
  return `${edge.source}-${edge.relationship}-${edge.target}`;
}

function edgeText(edge: GraphEdge, source: PositionedNode, target: PositionedNode) {
  const point = edgeLabelPoint(source, target);
  return (
    <text x={point.x} y={point.y}>
      {edge.relationship}
    </text>
  );
}

function edgePathElement(edge: GraphEdge, source: PositionedNode, target: PositionedNode) {
  return <path d={edgePath(source, target)} />;
}

function visibleEdges(edges: GraphEdge[], nodeById: Map<string, PositionedNode>) {
  return sortedEdges(edges).filter((edge) => nodeById.has(edge.source) && nodeById.has(edge.target));
}

function positionedNode(node: PositionedNode, edges: GraphEdge[], nodeById: Map<string, PositionedNode>) {
  const connected = connectedSides(node, edges, nodeById);
  return (
    <div className={positionedNodeClass(node)} key={node.id} style={nodeStyle(node)}>
      <AnchorDots connected={connected} />
      <span className="mono muted">{node.kind}</span>
      <strong>{node.label}</strong>
      {node.risk ? <p>Risk: {node.risk}</p> : null}
    </div>
  );
}

function graphEdge(edge: GraphEdge, nodeById: Map<string, PositionedNode>) {
  const source = nodeById.get(edge.source);
  const target = nodeById.get(edge.target);
  if (!source || !target) return null;
  return (
    <g key={edgeKey(edge)}>
      {edgePathElement(edge, source, target)}
      {edgeText(edge, source, target)}
    </g>
  );
}

function attackMapInnerStyle(layout: Layout) {
  return {
    width: layout.width,
    height: layout.height,
  };
}

function AttackMapGraph({ layout, edges }: { layout: Layout; edges: GraphEdge[] }) {
  const nodeById = new Map(layout.nodes.map((node) => [node.id, node]));
  const graphEdges = visibleEdges(edges, nodeById);
  return (
    <div className="attack-canvas-inner" style={attackMapInnerStyle(layout)}>
      <svg className="attack-edges" viewBox={`0 0 ${layout.width} ${layout.height}`} aria-hidden="true">
        {graphEdges.map((edge) => graphEdge(edge, nodeById))}
      </svg>
      {layout.nodes.map((node) => positionedNode(node, graphEdges, nodeById))}
    </div>
  );
}

function emptyState() {
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

function attackCanvas(layout: Layout, edges: GraphEdge[]) {
  return (
    <div className="attack-canvas attack-canvas-scroll" style={canvasStyle(layout)} aria-label="Attack map">
      <AttackMapGraph layout={layout} edges={edges} />
    </div>
  );
}

function graphData(scan: Scan) {
  const graph = scan.code_graph ?? { nodes: [], edges: [] };
  return {
    nodes: graph.nodes ?? [],
    edges: graph.edges ?? [],
  };
}

export function AttackMapPanel({ scan }: { scan: Scan }) {
  const graph = graphData(scan);
  const layout = positionNodes(graph.nodes, graph.edges);
  if (!layout.nodes.length) {
    return emptyState();
  }
  return attackCanvas(layout, graph.edges);
}
