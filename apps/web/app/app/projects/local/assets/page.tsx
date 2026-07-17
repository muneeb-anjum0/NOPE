import Link from "next/link";
import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { getProjects, getScans, selectScan } from "@/lib/nope-data";
import type { Scan } from "@/lib/types";

type AssetRow = {
  name: string;
  detail: string;
  status: string;
};

type FolderGroup = {
  folder: string;
  files: string[];
};

type AssetInventory = {
  fileCount: number;
  directoryCount: number;
  capped: boolean;
  folders: FolderGroup[];
  routes: AssetRow[];
  evidenceFiles: AssetRow[];
  dataAndRisk: AssetRow[];
  scanners: AssetRow[];
  stack: AssetRow[];
  scope: AssetRow[];
};

function unique(values: Array<string | null | undefined>) {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value)))).sort((a, b) => a.localeCompare(b));
}

function formatScanTime(scan: Scan | null) {
  const value = scan?.started_at ?? scan?.completed_at;
  if (!value) return "no scan selected";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function severitySummary(scan: Scan) {
  const counts = scan.findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
    return acc;
  }, {});
  return ["critical", "high", "medium", "low", "info"]
    .filter((severity) => counts[severity])
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(", ") || "No findings";
}

function parentFolder(file: string) {
  const index = file.lastIndexOf("/");
  return index > 0 ? file.slice(0, index) : "(repository root)";
}

function pluralize(count: number, noun: string) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function rowsFromValues(values: string[], fallback: string, status: string, detail: string): AssetRow[] {
  if (!values.length) return [{ name: fallback, detail: "No evidence mapped in the selected folder scan.", status: "Empty" }];
  return values.map((value) => ({ name: value, detail, status }));
}

function repositoryFolders(scan: Scan) {
  const scaffold = scan.repository_scaffold ?? [];
  const files = scaffold
    .filter((entry) => entry.startsWith("file:"))
    .map((entry) => entry.slice("file:".length));
  const grouped = files.reduce<Map<string, string[]>>((groups, file) => {
    const folder = parentFolder(file);
    const name = folder === "(repository root)" ? file : file.slice(folder.length + 1);
    groups.set(folder, [...(groups.get(folder) ?? []), name]);
    return groups;
  }, new Map());
  return {
    fileCount: files.length,
    directoryCount: scaffold.filter((entry) => entry.startsWith("dir:")).length,
    capped: scaffold.length >= 800,
    folders: Array.from(grouped.entries())
      .map(([folder, folderFiles]) => ({ folder, files: folderFiles.sort((a, b) => a.localeCompare(b)) }))
      .sort((a, b) => b.files.length - a.files.length || a.folder.localeCompare(b.folder)),
  };
}

function buildInventory(scan: Scan | null): AssetInventory | null {
  if (!scan) return null;
  const repo = repositoryFolders(scan);
  const nodes = scan.code_graph?.nodes ?? [];
  const routes = unique(nodes.filter((node) => node.kind === "entry point").map((node) => node.label));
  const evidenceFiles = unique([
    ...nodes.filter((node) => node.kind === "file").map((node) => node.file ?? node.label),
    ...scan.findings.map((finding) => finding.affected_file),
  ]);
  const dataAndRisk = unique(
    nodes
      .filter((node) => ["database", "authorization", "login"].includes(node.kind))
      .map((node) => `${node.kind}: ${node.label}${node.risk ? ` (${node.risk})` : ""}`),
  );
  const scope = unique([scan.repository_name, scan.target_url, scan.branch, scan.commit_sha]).map((value) => ({
    name: value,
    detail: "Scope metadata tied to this folder scan.",
    status: "Scoped",
  }));

  return {
    ...repo,
    routes: rowsFromValues(routes, "No routes mapped", "Mapped", "HTTP entry point from the selected scan."),
    evidenceFiles: rowsFromValues(evidenceFiles, "No evidence files mapped", "Evidence", "Used by a finding, scanner signal, or attack-map edge."),
    dataAndRisk: rowsFromValues(dataAndRisk, "No downstream risk nodes", "Mapped", "Data, auth, login, or risk node from the attack graph."),
    scanners: scan.scanner_runs.length
      ? scan.scanner_runs.map((run) => ({
          name: run.scanner,
          detail: run.message || `${run.findings_count} findings; ${(run.coverage_categories ?? []).join(", ") || "no coverage category"}`,
          status: run.status,
        }))
      : [{ name: "No scanner runs", detail: "Run a scan to populate scanner evidence.", status: "Pending" }],
    stack: scan.stack?.length
      ? scan.stack.map((item) => ({
          name: item.technology,
          detail: `${item.category}${item.confidence ? `; ${item.confidence} confidence` : ""}`,
          status: "Detected",
        }))
      : [{ name: "No stack detected", detail: "No framework or runtime evidence is available yet.", status: "Pending" }],
    scope: scope.length ? scope : [{ name: scan.id, detail: severitySummary(scan), status: "Selected" }],
  };
}

function AssetChip({ label, value }: { label: string; value: string | number }) {
  return <span className="asset-chip"><strong>{value}</strong>{label}</span>;
}

function FolderTile({ group }: { group: FolderGroup }) {
  return (
    <details className="asset-ledger-row asset-folder-tile">
      <summary>
        <strong>{group.folder}</strong>
        <span className="muted">{pluralize(group.files.length, "file")} indexed here</span>
        <span className="asset-folder-count mono">{group.files.length}</span>
      </summary>
      <div className="asset-file-cloud">
        {group.files.map((file) => <span key={`${group.folder}-${file}`}>{file}</span>)}
      </div>
    </details>
  );
}

function AssetDrawer({ title, rows, accent }: { title: string; rows: AssetRow[]; accent: string }) {
  return (
    <details className="asset-ledger-row asset-drawer">
      <summary>
        <strong>{title}</strong>
        <span className="muted">{pluralize(rows.length, "item")}</span>
        <span className={`asset-accent-dot ${accent}`} aria-hidden="true" />
      </summary>
      <div className="asset-drawer-body">
        {rows.map((row) => (
          <div className="asset-row" key={`${title}-${row.name}`}>
            <strong>{row.name}</strong>
            <span>{row.detail}</span>
            <em>{row.status}</em>
          </div>
        ))}
      </div>
    </details>
  );
}

export default async function AssetsPage({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.scan);
  const inventory = buildInventory(scan);

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Assets</p>
          <h1><PinkDotText text="Inventory the exposed surface." /></h1>
          <p>
            {activeProject
              ? `${activeProject.name}: ${scans.length} folder scans; selected ${scan?.repository_name ?? scan?.id ?? "none"} from ${formatScanTime(scan)}.`
              : "Create or open a scan folder to inventory its exposed surface."}
          </p>
        </div>
        {activeProject ? (
          <Link className="button ghost" href={`/app/projects/local/scans/${encodeURIComponent(activeProject.id)}`}>
            Open folder
          </Link>
        ) : null}
      </section>

      {inventory ? (
        <section className="asset-manifest">
          <div className="asset-manifest-bar">
            <div>
              <h2>Asset manifest</h2>
              <p>{inventory.fileCount}{inventory.capped ? "+" : ""} files and {inventory.directoryCount}{inventory.capped ? "+" : ""} directories indexed before evidence filtering.</p>
            </div>
            <div className="asset-chip-row">
              <AssetChip label="files" value={`${inventory.fileCount}${inventory.capped ? "+" : ""}`} />
              <AssetChip label="folders" value={inventory.folders.length} />
              <AssetChip label="evidence" value={inventory.evidenceFiles.length} />
              <AssetChip label="routes" value={inventory.routes.length} />
              {inventory.capped ? <span className="severity-pill severity-info">scaffold cap reached</span> : null}
            </div>
          </div>

          <div className="asset-manifest-grid">
            <section className="asset-ledger">
              <div className="asset-ledger-title">
                <span>Repository folders</span>
                <span className="mono muted">{inventory.folders.length}</span>
              </div>
              {inventory.folders.length ? (
                inventory.folders.map((group) => <FolderTile group={group} key={group.folder} />)
              ) : (
                <p className="muted">No repository file map is available for this scan.</p>
              )}
            </section>

            <section className="asset-ledger">
              <div className="asset-ledger-title">
                <span>Security signals</span>
                <span className="mono muted">6 groups</span>
              </div>
              <AssetDrawer accent="is-pink" rows={inventory.evidenceFiles} title="Evidence files" />
              <AssetDrawer accent="is-blue" rows={inventory.routes} title="Routes" />
              <AssetDrawer accent="is-orange" rows={inventory.dataAndRisk} title="Data and risk" />
              <AssetDrawer accent="is-green" rows={inventory.scanners} title="Scanners" />
              <AssetDrawer accent="is-yellow" rows={inventory.stack} title="Stack" />
              <AssetDrawer accent="is-muted" rows={inventory.scope} title="Scope" />
            </section>
          </div>
        </section>
      ) : (
        <div className="app-panel">
          <div className="panel-title">
            <h2>No assets yet</h2>
            <span className="mono muted">folder empty</span>
          </div>
          <p className="muted">Run a scan inside a project folder to build the asset atlas.</p>
        </div>
      )}
    </>
  );
}
