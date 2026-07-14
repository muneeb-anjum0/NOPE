import {
  Activity,
  AlertTriangle,
  Boxes,
  FileText,
  Gauge,
  GitBranch,
  Map,
  Play,
  Radar,
  Settings,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { api } from "@/lib/api";

type Finding = {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  category: string;
  affected_file?: string | null;
  affected_route?: string | null;
  confidence: string;
  scanner_sources: string[];
  status: string;
  remediation: string;
};

type Scan = {
  id: string;
  status: string;
  verdict: string;
  score: number;
  coverage_percent: number;
  target_url?: string | null;
  repository_name?: string | null;
  branch?: string | null;
  commit_sha?: string | null;
  findings: Finding[];
  coverage: Array<{ domain: string; status: string; notes: string; scanners: string[] }>;
  scanner_runs: Array<{ scanner: string; status: string; message: string; findings_count: number }>;
  code_graph: { nodes: Array<{ id: string; label: string; kind: string; risk?: string | null }> };
  ai_review: { status: string; provider: string; model?: string | null; message: string };
};

async function loadLatestScan(): Promise<Scan | null> {
  try {
    const scans = await api<Scan[]>("/api/scans");
    return scans[0] ?? null;
  } catch {
    return null;
  }
}

function severityClass(severity: string) {
  return `severity ${severity}`;
}

function count(findings: Finding[], severity: string) {
  return findings.filter((finding) => finding.severity === severity).length;
}

export default async function Dashboard() {
  const scan = await loadLatestScan();
  const findings = scan?.findings ?? [];
  const coverage = scan?.coverage ?? [];

  return (
    <div className="app">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark">N</div>
          <div>
            <strong>NOPE</strong>
            <span>Evidence over vibes</span>
          </div>
        </div>
        <nav className="nav">
          <a className="active" href="#overview"><Gauge size={17} />Overview</a>
          <a href="#findings"><ShieldAlert size={17} />Findings</a>
          <a href="#attack-map"><Map size={17} />Attack Map</a>
          <a href="#coverage"><Radar size={17} />Coverage</a>
          <a href="#scans"><Activity size={17} />Scans</a>
          <a href="#assets"><Boxes size={17} />Assets</a>
          <a href="#reports"><FileText size={17} />Reports</a>
          <a href="#settings"><Settings size={17} />Settings</a>
        </nav>
        <div className="sidebar-footer">
          Local project<br />
          Not tested is not secure.
        </div>
      </aside>
      <main className="main">
        <div className="topbar">
          <select className="project-select" aria-label="Project selector" defaultValue="demo">
            <option value="demo">NOPE Local Demo</option>
          </select>
          <a className="button" href="#onboarding"><Play size={16} />Run scan</a>
        </div>
        <div className="content">
          <section id="overview" className="grid">
            <div>
              <p className="muted">Your app works. That does not mean it is secure.</p>
              <h1>{scan?.verdict ?? "Let’s see what you’ve done."}</h1>
              <p className="muted">
                {scan
                  ? `Last scan ${scan.id} checked ${scan.repository_name ?? "no repository"} ${scan.target_url ? `and ${scan.target_url}` : ""}.`
                  : "Upload a repository ZIP or scan an authorized URL to get evidence-backed results."}
              </p>
            </div>
            <div className="grid cols-4">
              <div className="card metric"><span>Score</span><strong>{scan?.score ?? 0}</strong></div>
              <div className="card metric"><span>Coverage</span><strong>{scan?.coverage_percent ?? 0}%</strong></div>
              <div className="card metric"><span>Critical</span><strong>{count(findings, "critical")}</strong></div>
              <div className="card metric"><span>High</span><strong>{count(findings, "high")}</strong></div>
            </div>
          </section>

          <section id="onboarding" className="band">
            <h2>Let’s see what you’ve done.</h2>
            <form className="form" action="/api/start-scan" method="post" encType="multipart/form-data">
              <div className="field">
                <label htmlFor="repository">Repository ZIP</label>
                <input id="repository" name="repository" type="file" accept=".zip" />
              </div>
              <div className="field">
                <label htmlFor="targetUrl">Authorized deployed URL</label>
                <input id="targetUrl" name="targetUrl" type="url" placeholder="https://your-app.example" />
              </div>
              <div className="field">
                <label htmlFor="depth">Scan depth</label>
                <select id="depth" name="depth" defaultValue="full">
                  <option value="quick">Quick: secrets, dependencies, headers</option>
                  <option value="full">Full: repository, code graph, custom rules, AI review</option>
                  <option value="deep">Deep: sandbox and dynamic testing when configured</option>
                </select>
              </div>
              <label>
                <input name="confirmed" type="checkbox" /> I own this target or have explicit permission to test it.
              </label>
              <button className="button danger" type="submit"><Upload size={16} />Start scan</button>
            </form>
          </section>

          <section id="findings" className="card">
            <h2>Findings</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Location</th>
                  <th>Evidence</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr><td colSpan={5}>No findings yet. No scan evidence has been produced.</td></tr>
                ) : findings.map((finding) => (
                  <tr key={finding.id}>
                    <td><span className={severityClass(finding.severity)}>{finding.severity}</span></td>
                    <td><strong>{finding.title}</strong><br /><span className="muted">{finding.category} · {finding.confidence}</span></td>
                    <td>{finding.affected_file ?? finding.affected_route ?? "n/a"}</td>
                    <td>{finding.scanner_sources.join(" + ")}</td>
                    <td>{finding.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section id="attack-map" className="split">
            <div className="card">
              <h2>Attack Map</h2>
              <div className="node-map" aria-label="Attack surface map">
                {(scan?.code_graph.nodes ?? []).slice(0, 8).map((node, index) => (
                  <div
                    className="map-node"
                    key={node.id}
                    style={{ left: 24 + (index % 3) * 220, top: 24 + Math.floor(index / 3) * 120 }}
                  >
                    <strong>{node.label}</strong>
                    <p className="muted">{node.kind}{node.risk ? ` · ${node.risk}` : ""}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="card">
              <h2>Finding Detail</h2>
              {findings[0] ? (
                <>
                  <span className={severityClass(findings[0].severity)}>{findings[0].severity}</span>
                  <h3>{findings[0].title}</h3>
                  <p>{findings[0].remediation}</p>
                  <div className="grid cols-3">
                    <button className="button secondary" type="button">Explain</button>
                    <button className="button secondary" type="button">Generate fix</button>
                    <button className="button secondary" type="button">Regression test</button>
                  </div>
                </>
              ) : <p className="muted">Open a finding after a scan to inspect evidence, code flow, fix guidance, tests, and history.</p>}
            </div>
          </section>

          <section id="coverage" className="card">
            <h2>Coverage</h2>
            <p className="muted">Not tested does not mean secure.</p>
            <table className="table">
              <tbody>
                {coverage.map((record) => (
                  <tr key={record.domain}>
                    <td><strong>{record.domain}</strong></td>
                    <td>{record.status}</td>
                    <td>{record.scanners.join(", ") || "No scanner"}</td>
                    <td>{record.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section id="scans" className="grid cols-3">
            <div className="card"><h2>Scan History</h2><p>{scan ? `${scan.id} · ${scan.status}` : "No scans yet."}</p></div>
            <div className="card"><h2>AI Review</h2><p>{scan?.ai_review.message ?? "Qwen is configurable but not required for deterministic scans."}</p></div>
            <div className="card"><h2>Scanner Runs</h2><p>{scan?.scanner_runs.map((run) => `${run.scanner}: ${run.status}`).join(", ") ?? "No scanner runs yet."}</p></div>
          </section>

          <section id="assets" className="card">
            <h2>Assets</h2>
            <p className="muted">Repository, routes, scanners, target URL, branch, commit, and coverage metadata are captured per scan.</p>
          </section>

          <section id="reports" className="card">
            <h2>Reports</h2>
            <p className="muted">Exports are available from the API as JSON, Markdown, and SARIF. Formal reports avoid sarcastic language.</p>
          </section>

          <section id="settings" className="card">
            <h2>Settings</h2>
            <div className="grid cols-3">
              <div><GitBranch size={18} /><h3>GitHub</h3><p className="muted">Adapter contract exists. Production App credentials still required.</p></div>
              <div><AlertTriangle size={18} /><h3>Scan policy</h3><p className="muted">Scope, rate, artifact, AI, and scanner limits are API-enforced.</p></div>
              <div><Radar size={18} /><h3>Qwen model</h3><p className="muted">Provider, endpoint, model path, context, GPU layers, and timeouts are configurable.</p></div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
