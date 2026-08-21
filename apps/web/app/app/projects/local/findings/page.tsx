import { AIFindingActions } from "@/components/ai-finding-actions";
import { FindingDetailFocus } from "@/components/finding-detail-focus";
import { FilterSelect } from "@/components/filter-select";
import { FindingTable } from "@/components/finding-table";
import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { freshScan, getFindingDetail, getFindingObservations, getFindings, getProjects, getScans, selectScan, severityClass } from "@/lib/nope-data";
import type { FindingDetail } from "@/lib/types";

type PageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

function paramsFrom(input: Record<string, string | string[] | undefined>) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(input)) {
    if (Array.isArray(value)) {
      value.forEach((entry) => params.append(key, entry));
    } else if (value) {
      params.set(key, value);
    }
  }
  return params;
}

function hrefWith(params: URLSearchParams, updates: Record<string, string | number | null>) {
  const next = new URLSearchParams(params.toString());
  for (const [key, value] of Object.entries(updates)) {
    if (value === null || value === "") {
      next.delete(key);
    } else {
      next.set(key, String(value));
    }
  }
  return `/app/projects/local/findings?${next.toString()}`;
}

function SlashMeta({ items }: { items: Array<string | null | undefined> }) {
  const visible = items.filter((item): item is string => Boolean(item));
  return (
    <>
      {visible.map((item, index) => (
        <span key={`${item}-${index}`}>
          {index > 0 ? <span className="hot-slash"> / </span> : null}
          {item}
        </span>
      ))}
    </>
  );
}

export default async function FindingsPage({ searchParams }: PageProps) {
  const resolved = (await searchParams) ?? {};
  const params = paramsFrom(resolved);
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.get("scan")) ?? freshScan();
  const view = params.get("view") ?? "actionable";
  const findingsQuery = new URLSearchParams(params.toString());
  findingsQuery.set("page", "1");
  findingsQuery.set("page_size", "100");
  const dispositionByView: Record<string, string> = {
    conditional: "conditional",
    informational: "informational",
    withheld: "withheld",
    rejected: "rejected",
    raw: "raw",
  };
  const loaded = view === "actionable"
    ? await getFindings(scan.id, findingsQuery)
    : await getFindingObservations(scan.id, dispositionByView[view] ?? "raw");
  const results = loaded ?? {
    scan_id: scan.id,
    total: scan.findings.length,
    page: 1,
    page_size: 100,
    pages: 1,
    sort: "severity",
    direction: "asc" as const,
    filters: {},
    items: scan.findings,
  };
  const selectedId = params.get("finding") ?? results.items[0]?.id ?? scan.findings[0]?.id;
  const tab = params.get("tab") ?? "overview";
  const detail = selectedId ? await getFindingDetail(scan.id, selectedId) : null;

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Findings</p>
          <h1><PinkDotText text="Evidence, not vibes." /></h1>
          <p>{activeProject ? `${activeProject.name}: server-backed filters, protected evidence, code context, and real graph flow.` : "Choose an active folder to inspect findings."}</p>
        </div>
      </section>

      <nav className="tab-row" aria-label="Finding disposition views">
        {[
          ["actionable", "Actionable"],
          ["conditional", "Conditional"],
          ["informational", "Informational"],
          ["withheld", "Withheld"],
          ["rejected", "Rejected / Noise"],
          ["raw", "Raw Scanner Observations"],
        ].map(([value, label]) => (
          <a key={value} className={view === value ? "active-tab" : ""} href={hrefWith(params, { view: value, finding: null, detail: null })}>{label}</a>
        ))}
      </nav>

      <form className="filter-bar" action="/app/projects/local/findings">
        <input name="scan" type="hidden" value={scan.id} />
        <div className="filter-primary">
          <input name="query" placeholder="Search title, file, evidence" defaultValue={params.get("query") ?? ""} />
          <FilterSelect
            name="severity"
            label="Severity"
            defaultValue={params.get("severity") ?? ""}
            options={["critical", "high", "medium", "low", "info"].map((value) => ({ label: value, value }))}
          />
          <FilterSelect
            name="status"
            label="Status"
            defaultValue={params.get("status") ?? ""}
            options={["new", "confirmed", "fixing", "fixed", "verified", "false positive", "accepted risk", "suppressed", "reopened", "reintroduced"].map((label) => ({ label, value: label.replaceAll(" ", "_") }))}
          />
          <button type="submit">Apply</button>
          <a className="button-secondary" href={`/app/projects/local/findings?scan=${encodeURIComponent(scan.id)}`}>Clear</a>
        </div>
        <details className="filter-advanced">
          <summary>Advanced filters</summary>
          <div>
            <select name="confidence" defaultValue={params.get("confidence") ?? ""}>
              <option value="">Confidence</option>
              {["confirmed", "high", "medium", "low", "uncertain"].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <input name="scanner" placeholder="Scanner" defaultValue={params.get("scanner") ?? ""} />
            <input name="cwe" placeholder="CWE" defaultValue={params.get("cwe") ?? ""} />
            <input name="file" placeholder="File" defaultValue={params.get("file") ?? ""} />
            <input name="route" placeholder="Route" defaultValue={params.get("route") ?? ""} />
            <select name="sort" defaultValue={params.get("sort") ?? "severity"}>
              {["severity", "confidence", "status", "scanner", "file", "route", "first_seen", "last_seen", "title"].map((value) => <option key={value} value={value}>Sort: {value}</option>)}
            </select>
            <select name="direction" defaultValue={params.get("direction") ?? "asc"}>
              <option value="asc">Ascending</option>
              <option value="desc">Descending</option>
            </select>
          </div>
        </details>
      </form>

      <div className="findings-stack" data-brand-skip>
        <FindingDetailFocus />
        <FindingDetailPanel detail={detail} tab={tab} params={params} scanId={scan.id} />
        <FindingTable findings={results.items} scanId={scan.id} selectedId={selectedId} searchQuery={params.toString()} total={results.total} />
      </div>
    </>
  );
}

function FindingDetailPanel({ detail, tab, params, scanId }: { detail: FindingDetail | null; tab: string; params: URLSearchParams; scanId: string }) {
  if (!detail) {
    return (
      <div className="app-panel">
        <div className="panel-title"><h2>Finding detail</h2></div>
        <p className="muted">Select a finding to inspect evidence.</p>
      </div>
    );
  }
  const finding = detail.finding;
  const tabs = ["overview", "evidence", "code", "code_flow", "fix", "tests", "history"];
  const expanded = params.get("detail") === "open";
  return (
    <details className="collapse-panel finding-detail-panel" open={expanded}>
      <summary className="finding-detail-summary">
        <div>
          <p className="detail-eyebrow">Finding detail</p>
          <div className="detail-title-row">
            <h2>{finding.title}</h2>
            <span className="detail-sign" aria-hidden="true" />
          </div>
        </div>
        <div className="detail-summary-actions">
          <span className={severityClass(finding.severity)}>{finding.severity}</span>
        </div>
      </summary>
      <div className="collapse-body finding-detail-body">
        <div className="tab-row detail-tab-row">
          {tabs.map((name) => (
            <a key={name} className={tab === name ? "active-tab" : ""} href={hrefWith(params, { tab: name, detail: "open" })}>{name.replace("_", " ")}</a>
          ))}
        </div>
        {tab === "overview" && <Overview detail={detail} scanId={scanId} />}
        {tab === "evidence" && <Evidence detail={detail} />}
        {tab === "code" && <Code detail={detail} />}
        {tab === "code_flow" && <CodeFlow detail={detail} />}
        {tab === "fix" && <Fix detail={detail} />}
        {tab === "tests" && <Tests detail={detail} />}
        {tab === "history" && <History detail={detail} />}
      </div>
    </details>
  );
}

function Overview({ detail, scanId }: { detail: FindingDetail; scanId: string }) {
  const finding = detail.finding;
  return (
    <div className="detail-stack">
      <p className="muted">{finding.description}</p>
      <dl className="detail-grid">
        <div><dt>Disposition</dt><dd>{finding.disposition ?? "confirmed"}</dd></div>
        <div><dt>Priority</dt><dd>{finding.priority ?? "normal"}</dd></div>
        <div><dt>Exposure</dt><dd>{finding.exposure ?? "unproven"}</dd></div>
        <div><dt>Reachability</dt><dd>{finding.reachability ?? "UNKNOWN"}</dd></div>
        <div><dt>Data sensitivity</dt><dd>{finding.data_sensitivity ?? "UNKNOWN"}</dd></div>
        <div><dt>Execution context</dt><dd>{finding.execution_contexts?.join(" / ") || "UNKNOWN"}</dd></div>
        <div><dt>Actionability</dt><dd>{finding.actionability ?? "manual review required"}</dd></div>
        <div><dt>Confidence</dt><dd>{finding.confidence}</dd></div>
        <div><dt>Status</dt><dd>{finding.status}</dd></div>
        <div><dt>Rule</dt><dd>{finding.nope_rule_id ?? finding.original_rule_id ?? "n/a"}</dd></div>
        <div><dt>CWE <span className="hot-slash">/</span> OWASP</dt><dd><SlashMeta items={[finding.cwe ?? "n/a", finding.owasp ?? "n/a"]} /></dd></div>
        <div><dt>Location</dt><dd className="mono">{finding.affected_file ?? finding.affected_route ?? "n/a"}</dd></div>
        <div><dt>Scanner</dt><dd>{finding.scanner_sources.join(" + ") || "n/a"}</dd></div>
      </dl>
      <div className="evidence-card">
        <strong>Why NOPE classified this signal</strong>
        <p>{finding.disposition_reason ?? "Historical finding without a stored disposition explanation."}</p>
        <p className="mono muted">{finding.disposition_reason_codes?.join(" / ") || "HISTORICAL_DEFAULT"}</p>
        {finding.compensating_controls?.map((control) => <p key={control}>Compensating control: {control}</p>)}
      </div>
      {finding.promotion_proof?.length ? (
        <div className="evidence-card">
          <strong>{finding.disposition === "confirmed" || finding.disposition === "confirmed_with_compensating_control" ? "Why NOPE promoted this" : "Why NOPE did not promote this"}</strong>
          <p className="mono muted">Proof contract: {finding.proof_contract ?? "contextual"}</p>
          {finding.promotion_proof.map((step, index) => (
            <p key={`${step.fact}-${index}`}><strong>{step.fact.replaceAll("_", " ")}</strong>: {step.status} — {step.evidence}</p>
          ))}
          {finding.negative_evidence?.map((item) => <p key={item}>Negative evidence: {item}</p>)}
        </div>
      ) : null}
      <AIFindingActions finding={finding} scanId={scanId} />
    </div>
  );
}

function Evidence({ detail }: { detail: FindingDetail }) {
  return (
    <div className="detail-stack">
      {detail.evidence.length === 0 ? <p className="muted">No evidence records are attached.</p> : detail.evidence.map((evidence, index) => (
        <div className="evidence-card" key={index}>
          <strong>{String(evidence.source ?? "Evidence")}</strong>
          <p className="mono muted">{String(evidence.file ?? evidence.route ?? "n/a")}:{String(evidence.line ?? "")}</p>
          <p>{String(evidence.message ?? "")}</p>
          {evidence.snippet ? <pre>{String(evidence.snippet)}</pre> : null}
          {evidence.raw_artifact_id ? <span className="severity-pill severity-info">raw artifact protected</span> : null}
        </div>
      ))}
    </div>
  );
}

function Code({ detail }: { detail: FindingDetail }) {
  const source = detail.source;
  if (!source || !source.available) {
    return <p className="muted">{source?.message ?? "Source code is not available for this finding."}</p>;
  }
  const lines = source.code.split("\n");
  return (
    <div className="code-viewer">
      <div className="mono muted">{source.file}:{source.start_line}-{source.end_line}</div>
      <pre>{lines.map((line, index) => {
        const number = source.start_line + index;
        return <span key={number} className={source.highlighted_lines.includes(number) ? "highlight-line" : ""}><span className="line-number">{number}</span>{line}{"\n"}</span>;
      })}</pre>
    </div>
  );
}

function CodeFlow({ detail }: { detail: FindingDetail }) {
  const flow = detail.code_flow;
  if (!flow.available) {
    return <p className="muted">{flow.message}</p>;
  }
  return (
    <div className="flow-list">
      {flow.edges.map((edge) => (
        <div className="flow-edge" key={`${edge.source}-${edge.relationship}-${edge.target}`}>
          <span className="mono">{edge.source}</span>
          <span>{edge.relationship}</span>
          <span className="mono">{edge.target}</span>
        </div>
      ))}
    </div>
  );
}

function Fix({ detail }: { detail: FindingDetail }) {
  return <p className="muted">{detail.finding.remediation}</p>;
}

function Tests({ detail }: { detail: FindingDetail }) {
  return <p className="muted">{detail.finding.test_guidance ?? "No regression test guidance has been generated yet."}</p>;
}

function History({ detail }: { detail: FindingDetail }) {
  return (
    <div className="detail-stack">
      {detail.history.map((item, index) => (
        <div className="collapse-row" key={`${item.event}-${index}`}>
          <strong>{item.event}</strong>
          <span className="muted">{new Date(item.at).toLocaleString()}</span>
          <span className="severity-pill severity-info">{JSON.stringify(item.data)}</span>
        </div>
      ))}
    </div>
  );
}
