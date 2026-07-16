import { PinkDotText } from "@/components/pink-dot-text";

const assetGroups = [
  {
    title: "Routes",
    summary: "HTTP entry points discovered from repository and deployed URL evidence.",
    rows: [
      ["Public routes", "Landing, auth, API route handlers, and upload endpoints.", "Mapped"],
      ["Protected routes", "Dashboard surfaces require a local session before render.", "Gated"],
      ["Dynamic routes", "Parameter-based paths are queued for IDOR checks.", "Watched"],
    ],
  },
  {
    title: "Data Systems",
    summary: "Databases, auth stores, and policy surfaces used by the app.",
    rows: [
      ["Postgres", "Stores local users, sessions, scan state, and future project data.", "Local"],
      ["Redis", "Queues worker jobs and temporary scan coordination.", "Service"],
      ["RLS targets", "Supabase-style row policies are tracked when detected.", "Coverage"],
    ],
  },
  {
    title: "Storage",
    summary: "Object buckets and uploaded evidence that need access review.",
    rows: [
      ["MinIO", "Stores report artifacts and scanner evidence in development.", "Local"],
      ["Upload paths", "Repository zip uploads are extracted into isolated workspaces.", "Scoped"],
      ["Public buckets", "Bucket exposure checks run when storage config is present.", "Queued"],
    ],
  },
  {
    title: "External Calls",
    summary: "Network destinations, model runtimes, and third-party integrations.",
    rows: [
      ["Target URL", "Authorized web targets are scanned only after scope validation.", "Required"],
      ["Qwen runtime", "Local llama.cpp receives focused evidence, not shell access.", "Optional"],
      ["GitHub", "PR automation remains partial until credentials are configured.", "Partial"],
    ],
  },
];

export default function AssetsPage() {
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Assets</p>
          <h1><PinkDotText text="Inventory the exposed surface." /></h1>
          <p>Routes, frameworks, storage, external calls, scanners, targets, commits, and runtime gaps.</p>
        </div>
      </section>
      <div className="collapse-list">
        {assetGroups.map((group, index) => (
          <details className="collapse-panel settings-accordion" name="assets-sections" key={group.title} open={index === 0}>
            <summary>
              <span>
                <h2>{group.title}</h2>
                <p>{group.summary}</p>
              </span>
              <span className="mono muted">{group.rows.length} items</span>
            </summary>
            <div className="collapse-body">
              {group.rows.map(([name, detail, status]) => (
                <div className="collapse-row" key={name}>
                  <strong>{name}</strong>
                  <span className="muted">{detail}</span>
                  <span className="severity-pill severity-info">{status}</span>
                </div>
              ))}
            </div>
          </details>
        ))}
      </div>
    </>
  );
}
