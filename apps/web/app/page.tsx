import {
  ArrowRight,
  Brain,
  Code2,
  FileText,
  GitBranch,
  LockKeyhole,
  Network,
  Radar,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
} from "lucide-react";

const stages = [
  "Repository mapped",
  "Stack detected: Next.js + Supabase",
  "43 routes discovered",
  "18 scanner stages queued",
  "Qwen review scoped to evidence",
];

const findings = [
  ["critical", "Users can read other users' invoices"],
  ["high", "Service-role key entered the client bundle"],
  ["high", "Private storage bucket is publicly readable"],
];

const coverage = [
  ["Secrets", "key leaks"],
  ["Authentication", "session/auth flows"],
  ["Authorization", "server-side access"],
  ["IDOR", "cross-user data"],
  ["Dependencies", "known CVEs"],
  ["APIs", "route exposure"],
  ["Supabase", "client/RLS safety"],
  ["Storage", "bucket access"],
  ["Rate limiting", "abuse/cost controls"],
  ["AI cost abuse", "token burn"],
  ["Staging exposure", "debug surfaces"],
  ["Privacy", "third parties"],
  ["Dynamic testing", "runtime checks"],
];

const principles = [
  "Frontend route protection is not authorization.",
  "UUIDs do not prevent IDOR.",
  "Public Supabase keys require correct RLS.",
  "Hidden endpoints are not security.",
  "Scanner scores do not prove application security.",
];

const methodSteps = [
  ["Repository", GitBranch, "Map files, routes", "and config evidence."],
  ["Authorized URL", LockKeyhole, "Probe headers, cookies", "and public exposure."],
  ["Scanners", Radar, "Run tools that fit", "the detected stack."],
  ["Code graph", Code2, "Connect routes to", "data and sinks."],
  ["Focused RAG", TerminalSquare, "Retrieve only the", "evidence that matters."],
  ["Qwen", Brain, "Reason locally over", "bounded context."],
];

const evidenceLines = [
  ["01", "Scanner source", "Semgrep, Gitleaks, Trivy, Bandit, ZAP, sandbox, and NOPE rules stay separated in the finding record."],
  ["02", "Code context", "Evidence links back to file, route, line, snippet, scanner run, and raw artifact authorization."],
  ["03", "Drift memory", "Baselines preserve what changed between a trusted scan and the next modified scan."],
  ["04", "AI boundary", "Qwen explains and challenges focused evidence without becoming the primary source of truth."],
];

export default function LandingPage() {
  return (
    <main className="page-shell">
      <header className="landing-nav">
        <div className="container landing-nav-inner">
          <a className="wordmark" href="#top" aria-label="NOPE home">
            <span>NOPE<span className="wordmark-dot">.</span></span>
          </a>
          <nav className="landing-links" aria-label="Landing navigation">
            <a href="#product">Product</a>
            <a href="#method">Method</a>
            <a href="#coverage">Coverage</a>
            <a href="#local-ai">Local AI</a>
            <a href="#github">GitHub</a>
          </nav>
          <div className="hero-actions" style={{ marginTop: 0 }}>
            <a className="button ghost" href="/login">
              Open dashboard
            </a>
          </div>
        </div>
      </header>

      <section id="top" className="container hero">
        <div>
          <h1>
            NOPE<span className="wordmark-dot">.</span>
          </h1>
          <p className="hero-copy">
            Your app works. That does not mean it is secure. Connect your repository,
            add the deployed URL, and find what you should not ship.
          </p>
          <div className="hero-actions">
            <a className="button primary" href="/login">
              Open dashboard <ArrowRight size={15} />
            </a>
            <a className="button" href="#method">
              See how NOPE works
            </a>
          </div>
        </div>

        <div className="scan-console hero-console" aria-label="Animated demo scan">
          <div className="console-header">
            <span>demo/nope-demo</span>
            <span>demonstration data</span>
          </div>
          <div className="console-body">
            <div className="demo-stages">
              {stages.map((stage, index) => (
                <div className="stage-row" style={{ animationDelay: `${index * 90}ms` }} key={stage}>
                  <span>{stage}</span>
                  <span className="status-dot ok" aria-label="complete" />
                </div>
              ))}
            </div>
            <div className="demo-stats">
              <span><strong>2,847</strong> files mapped</span>
              <span><strong>43</strong> routes</span>
            </div>
            <div className="demo-findings">
              {findings.map(([severity, title]) => (
                <div className="demo-finding" key={title}>
                  <span className={`severity-pill severity-${severity}`}>{severity}</span>
                  <span>{title}</span>
                </div>
              ))}
            </div>
            <div className="demo-verdict">
              <ShieldAlert color="var(--critical)" />
              <div>
                <span className="mono muted">Final demo verdict</span>
                <strong>NOPE. Do not ship this.</strong>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="product" className="section">
        <div className="container">
          <p className="section-kicker">Why NOPE exists</p>
          <h2>Vibe-coded software can work while still being wildly unsafe.</h2>
          <div className="principle-board">
            <div>
              <p className="section-intro">
                Fast builders need security evidence, not a chatbot that says things sound fine.
                NOPE looks for server-side authorization gaps, exposed secrets, unsafe RLS,
                public storage, scanner failures, privacy leakage, and untested areas.
              </p>
            </div>
            <ol className="principle-list">
              {principles.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      <section id="method" className="section">
        <div className="container">
          <p className="section-kicker">Method</p>
          <h2>Deterministic evidence first. Focused reasoning second.</h2>
          <p className="section-intro">
            NOPE does not dump a whole repository into an LLM. It maps, scans, normalizes,
            connects, retrieves, reasons, tests, and records coverage gaps.
          </p>
          <div className="method-flow">
            {methodSteps.map(([label, Icon, line1, line2], index) => {
              const MethodIcon = Icon as typeof GitBranch;
              return (
                <div className="method-step" key={label as string}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <MethodIcon size={22} color="var(--brand-primary)" />
                  <strong>{label as string}</strong>
                  <p>
                    {line1 as string}
                    <br />
                    {line2 as string}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section id="coverage" className="section">
        <div className="container">
          <p className="section-kicker">Coverage</p>
          <h2>Not tested is not secure.</h2>
          <div className="coverage-lanes">
            {coverage.map(([item, detail], index) => (
              <div className="coverage-chip" key={item}>
                <span className="mono">{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{item}</strong>
                  <em>{detail}</em>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="attack-map" className="section">
        <div className="container">
          <p className="section-kicker">Attack Map showcase</p>
          <h2>Routes, files, data access, and risk hints stay connected.</h2>
          <div className="showcase-grid">
            <div className="attack-canvas landing-map" aria-label="Static attack map showcase">
              {[
                ["entry", "ANY /api/invoices/:id", "entry point"],
                ["file", "app/api/invoices/[id]/route.ts", "handler file"],
                ["db", "prisma.invoice.findUnique", "database"],
                ["risk", "Missing ownership check", "authorization risk"],
              ].map(([id, label, kind]) => (
                <div className={`attack-node map-node-${id}`} key={id}>
                  <span className="mono muted">{kind}</span>
                  <strong style={{ display: "block", marginTop: 8 }}>{label}</strong>
                  {id === "risk" ? <p style={{ color: "var(--high)" }}>Risk: high</p> : null}
                </div>
              ))}
            </div>
            <div className="edge-proof">
              <div className="edge-proof-title">
                <Network size={16} />
                <span>graph evidence</span>
              </div>
              {["entry point handled by file", "file retrieves data from prisma", "file may reach missing ownership check", "finding detail shows real edges only"].map((item) => (
                <div className="edge-proof-row" key={item}>
                  <span />
                  <p>{item}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section id="evidence" className="section">
        <div className="container">
          <p className="section-kicker">Evidence showcase</p>
          <h2>Every scary sentence should have a source.</h2>
          <div className="showcase-grid">
            <div className="evidence-stack">
              {evidenceLines.map(([index, title, body]) => (
                <div className="evidence-line" key={title}>
                  <span>{index}</span>
                  <strong>{title}</strong>
                  <p>{body}</p>
                </div>
              ))}
            </div>
            <div className="export-rail">
              <div className="edge-proof-title">
                <FileText size={16} />
                <span>report chain</span>
              </div>
              {["JSON for automation", "Markdown for engineers", "SARIF for scanners", "PDF for review"].map((item) => (
                <div className="export-row" key={item}>
                  <span>{item.split(" ")[0]}</span>
                  <strong>{item.replace(`${item.split(" ")[0]} `, "")}</strong>
                  <em>export</em>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section id="local-ai" className="section">
        <div className="container editorial-grid">
          <div>
            <p className="section-kicker">Local AI</p>
            <h2>Qwen runs through llama.cpp. No Ollama dependency.</h2>
            <p className="section-intro">
              The local-AI path is designed for a Qwen3 8B Q4_K_M GGUF mounted read-only
              into a dedicated `nope-ai` service. The model receives focused evidence,
              not arbitrary shell access and not whole repositories.
            </p>
          </div>
          <div className="scan-console">
            <div className="console-header">
              <span>nope-ai</span>
              <span>llama.cpp</span>
            </div>
            <div className="console-body">
              {["Read-only model mount", "Bounded context", "Timeout enforced", "Failure-safe scans"].map((item) => (
                <div className="stage-row" key={item}>
                  <span>{item}</span>
                  <span className="status-dot ok" />
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section id="github" className="section">
        <div className="container">
          <p className="section-kicker">GitHub workflow</p>
          <h2>Find it. Explain it. Patch it. Prove it did not come back.</h2>
          <p className="section-intro">
            GitHub PR automation is intentionally marked partial until production credentials
            and permissions are configured. The local pipeline already produces findings,
            evidence, coverage, and exportable reports.
          </p>
          <div className="hero-actions">
            <a className="button primary" href="/login">
              Open local workspace <Sparkles size={15} />
            </a>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="container landing-footer-inner">
          <strong>NOPE.</strong>
          <span>Rules first. Local AI second. Evidence always.</span>
          <a href="/login">Open dashboard</a>
        </div>
      </footer>
    </main>
  );
}
