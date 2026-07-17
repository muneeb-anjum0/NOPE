import type { CSSProperties } from "react";
import type { Scan } from "@/lib/types";

type GraphNode = Scan["code_graph"]["nodes"][number];
type GraphEdge = NonNullable<Scan["code_graph"]["edges"]>[number];

type FlowRow = {
  id: string;
  entries: GraphNode[];
  file?: GraphNode;
  outcomes: Array<{ node: GraphNode; relationship: string }>;
};

const OUTCOME_ORDER: Record<string, number> = {
  authorization: 0,
  database: 1,
  login: 2,
};

function emptyState() {
  return (
    <div className="attack-flow-empty" aria-label="Attack map empty state">
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

function nodeById(nodes: GraphNode[]) {
  return new Map(nodes.map((node) => [node.id, node]));
}

function edgesFrom(edges: GraphEdge[], sourceId: string, relationship?: string) {
  return edges.filter((edge) => edge.source === sourceId && (!relationship || edge.relationship === relationship));
}

function sortOutcomes(items: Array<{ node: GraphNode; relationship: string }>) {
  return items.slice().sort((a, b) => {
    const kindDelta = (OUTCOME_ORDER[a.node.kind] ?? 9) - (OUTCOME_ORDER[b.node.kind] ?? 9);
    return kindDelta || a.node.label.localeCompare(b.node.label);
  });
}

function uniqueOutcomes(items: Array<{ node: GraphNode; relationship: string }>) {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.relationship}:${item.node.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildRows(nodes: GraphNode[], edges: GraphEdge[]): FlowRow[] {
  const lookup = nodeById(nodes);
  const rows: FlowRow[] = [];
  const seenFiles = new Set<string>();
  const entries = nodes.filter((node) => node.kind === "entry point");
  const fileGroups = new Map<string, { file: GraphNode; entries: GraphNode[] }>();

  for (const entry of entries) {
    const handled = edgesFrom(edges, entry.id, "handled by");
    if (!handled.length) {
      rows.push({ id: entry.id, entries: [entry], outcomes: [] });
      continue;
    }
    for (const edge of handled) {
      const file = lookup.get(edge.target);
      if (!file) continue;
      seenFiles.add(file.id);
      const group = fileGroups.get(file.id) ?? { file, entries: [] };
      group.entries.push(entry);
      fileGroups.set(file.id, group);
    }
  }

  for (const group of fileGroups.values()) {
    const outcomes = sortOutcomes(
      uniqueOutcomes(
        edgesFrom(edges, group.file.id)
          .map((child) => {
            const node = lookup.get(child.target);
            return node ? { node, relationship: child.relationship } : null;
          })
          .filter((item): item is { node: GraphNode; relationship: string } => Boolean(item)),
      ),
    );
    rows.push({ id: group.file.id, entries: group.entries, file: group.file, outcomes });
  }

  const orphanFiles = nodes.filter((node) => node.kind === "file" && !seenFiles.has(node.id));
  for (const file of orphanFiles) {
    const outcomes = sortOutcomes(
      uniqueOutcomes(
        edgesFrom(edges, file.id)
          .map((edge) => {
            const node = lookup.get(edge.target);
            return node ? { node, relationship: edge.relationship } : null;
          })
          .filter((item): item is { node: GraphNode; relationship: string } => Boolean(item)),
      ),
    );
    rows.push({ id: file.id, entries: [], file, outcomes });
  }

  return rows;
}

function kindClass(kind?: string) {
  return `attack-flow-card attack-flow-${(kind ?? "unknown").replaceAll(" ", "-")}`;
}

function FlowCard({ node, fallback }: { node?: GraphNode; fallback: string }) {
  if (!node) {
    return (
      <div className="attack-flow-card attack-flow-empty-card">
        <span className="mono muted">{fallback}</span>
        <strong>not mapped</strong>
      </div>
    );
  }
  return (
    <div className={kindClass(node.kind)}>
      <span className="mono muted">{node.kind}</span>
      <strong>{node.label}</strong>
      {node.risk ? <em>Risk: {node.risk}</em> : null}
    </div>
  );
}

function EntryStack({ entries }: { entries: GraphNode[] }) {
  if (!entries.length) return <FlowCard fallback="entry point" />;
  return (
    <div className="attack-flow-entry-stack">
      {entries.map((entry) => <FlowCard key={entry.id} node={entry} fallback="entry point" />)}
    </div>
  );
}

function OutcomeStack({ outcomes }: { outcomes: FlowRow["outcomes"] }) {
  if (!outcomes.length) return null;
  return (
    <div className="attack-flow-outcomes">
      {outcomes.map(({ node, relationship }) => (
        <div className={kindClass(node.kind)} key={`${relationship}-${node.id}`}>
          <span className="mono muted">{relationship}</span>
          <strong>{node.label}</strong>
          {node.risk ? <em>Risk: {node.risk}</em> : null}
        </div>
      ))}
    </div>
  );
}

function FlowRowView({ row, index }: { row: FlowRow; index: number }) {
  const hasOutcomes = row.outcomes.length > 0;
  return (
    <article className="attack-flow-row" style={{ "--row-index": index } as CSSProperties}>
      <EntryStack entries={row.entries} />
      <span className="attack-flow-link" aria-hidden="true">handled</span>
      <FlowCard node={row.file} fallback="file" />
      {hasOutcomes ? <span className="attack-flow-link" aria-hidden="true">reaches</span> : null}
      {hasOutcomes ? <OutcomeStack outcomes={row.outcomes} /> : null}
    </article>
  );
}

export function AttackMapPanel({ scan }: { scan: Scan }) {
  const graph = scan.code_graph ?? { nodes: [], edges: [] };
  const nodes = graph.nodes ?? [];
  const edges = graph.edges ?? [];
  const rows = buildRows(nodes, edges);

  if (!rows.length) return emptyState();

  return (
    <section className="attack-flow-board" aria-label="Attack map">
      <div className="attack-flow-header" aria-hidden="true">
        <span>entry</span>
        <span>file</span>
        <span>data / risk</span>
      </div>
      <div className="attack-flow-rows">
        {rows.map((row, index) => <FlowRowView index={index} key={row.id} row={row} />)}
      </div>
    </section>
  );
}
