import {
  ArrowRight,
  Brain,
  Code2,
  GitBranch,
  LockKeyhole,
  Radar,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
  TriangleAlert,
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

const methodSteps = [
  ["Repository", GitBranch, "Map files, routes", "and config evidence."],
  ["Authorized URL", LockKeyhole, "Probe headers, cookies", "and public exposure."],
  ["Scanners", Radar, "Run tools that fit", "the detected stack."],
  ["Code graph", Code2, "Connect routes to", "data and sinks."],
  ["Focused RAG", TerminalSquare, "Retrieve only the", "evidence that matters."],
  ["Qwen", Brain, "Reason locally over", "bounded context."],
];

export default function LandingPage() {
  return (
    <main className="page-shell">
      <header className="landing-nav">
        <div className="container landing-nav-inner">
          <a className="wordmark" href="#top" aria-label="NOPE home">
            <span>NOPE.</span>
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
            NOPE<span>.</span>
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

        <div className="scan-console" aria-label="Animated demo scan">
          <div className="console-header">
            <span>demo/nope-demo</span>
            <span>demonstration data</span>
          </div>
          <div className="console-body">
            <div className="stage-list">
              {stages.map((stage, index) => (
                <div className="stage-row" style={{ animationDelay: `${index * 90}ms` }} key={stage}>
                  <span>{stage}</span>
                  <span className="status-dot ok" aria-label="complete" />
                </div>
              ))}
            </div>
            <div className="stage-row">
              <span className="mono">2,847 files mapped</span>
              <span className="mono">43 routes</span>
            </div>
            {findings.map(([severity, title]) => (
              <div className="finding-row" key={title}>
                <div>
                  <span className={`severity-pill severity-${severity}`}>{severity}</span>
                  <div style={{ marginTop: 8 }}>{title}</div>
                </div>
                <TriangleAlert color={`var(--${severity})`} size={18} />
              </div>
            ))}
            <div className="finding-row">
              <div>
                <span className="mono muted">Final demo verdict</span>
                <h3 style={{ margin: "8px 0 0", fontSize: 28 }}>NOPE. Do not ship this.</h3>
              </div>
              <ShieldAlert color="var(--critical)" />
            </div>
          </div>
        </div>
      </section>

      <section id="product" className="section">
        <div className="container">
          <p className="section-kicker">Why NOPE exists</p>
          <h2>Vibe-coded software can work while still being wildly unsafe.</h2>
          <div className="editorial-grid">
            <div className="editorial-panel">
              <p className="section-intro" style={{ marginTop: 0 }}>
                Fast builders need security evidence, not a chatbot that says things sound fine.
                NOPE looks for server-side authorization gaps, exposed secrets, unsafe RLS,
                public storage, scanner failures, privacy leakage, and untested areas.
              </p>
            </div>
            <div className="editorial-panel">
              <ul className="danger-list">
                <li>Frontend route protection is not authorization.</li>
                <li>UUIDs do not prevent IDOR.</li>
                <li>Public Supabase keys require correct RLS.</li>
                <li>Hidden endpoints are not security.</li>
                <li>Scanner scores do not prove application security.</li>
              </ul>
            </div>
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
          <div className="coverage-matrix">
            {coverage.map(([item, detail], index) => (
              <div className="coverage-row" key={item}>
                <span className="mono">{String(index + 1).padStart(2, "0")}</span>
                <strong>{item}</strong>
                <em>{detail}</em>
              </div>
            ))}
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
    </main>
  );
}
