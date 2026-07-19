import Link from "next/link";
import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { freshScan, getProjects, getRulesV2Candidates, getRulesV2Summary, getScans, selectScan } from "@/lib/nope-data";
import type { RulesV2Candidate, RulesV2Decision, RulesV2Summary } from "@/lib/types";

const filters = [
  ["all", "All"],
  ["promoted", "Promoted"],
  ["withheld", "Withheld"],
  ["needs_manual_review", "Review"],
  ["rejected", "Rejected"],
] as const;

function numberValue(value: unknown) {
  return typeof value === "number" ? value : 0;
}

function metric(summary: RulesV2Summary | null, key: string) {
  return numberValue(summary?.coverage?.[key as keyof NonNullable<RulesV2Summary["coverage"]>]);
}

function buildQuery(scanId: string, result: string) {
  const params = new URLSearchParams();
  params.set("scan", scanId);
  if (result !== "all") params.set("result", result);
  return `/app/projects/local/rules?${params.toString()}`;
}

function resultLabel(decision: RulesV2Decision) {
  if (decision.result === "needs_manual_review") return "review";
  return decision.result || "unknown";
}

function CandidateRow({ candidate, decision }: { candidate: RulesV2Candidate; decision: RulesV2Decision }) {
  const location = [candidate.file, candidate.line ? `line ${candidate.line}` : null, candidate.route].filter(Boolean).join(" / ");
  const evidence = candidate.evidence?.[0];
  return (
    <details className={`rules-v2-candidate is-${decision.result}`}>
      <summary>
        <span className="rules-v2-result">{resultLabel(decision)}</span>
        <span>
          <strong>{candidate.rule_id}</strong>
          <small>{candidate.family ?? "unknown"} / {candidate.preliminary_severity ?? "unknown"} / {candidate.preliminary_confidence ?? "unknown"}</small>
        </span>
        <em>{location || candidate.source_type || "scan evidence"}</em>
      </summary>
      <div className="rules-v2-candidate-body">
        <p>{decision.reason ?? "No promotion-gate reason was recorded."}</p>
        <div className="rules-v2-mini-grid">
          <span><strong>Evidence</strong>{evidence?.message ?? "No evidence message recorded."}</span>
          <span><strong>Missing</strong>{candidate.missing_evidence?.join(", ") || decision.missing_evidence?.join(", ") || "none"}</span>
          <span><strong>Safe pattern</strong>{candidate.safe_pattern_evidence?.join(", ") || "none"}</span>
          <span><strong>Correlation</strong>{candidate.graph_references?.concat(decision.correlation_path ?? []).join(", ") || candidate.scanner_references?.join(", ") || "local context"}</span>
        </div>
        {evidence?.snippet ? <pre>{evidence.snippet}</pre> : null}
      </div>
    </details>
  );
}

function FamilyMatrix({ summary }: { summary: RulesV2Summary | null }) {
  const families = Object.entries(summary?.coverage?.by_family ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (!families.length) return <p className="muted">No family-level Rules v2 coverage has been recorded for this scan.</p>;
  return (
    <div className="rules-v2-family-grid">
      {families.map(([family, counts]) => (
        <div className="rules-v2-family" key={family}>
          <strong>{family}</strong>
          <span>{numberValue(counts.promoted)} promoted</span>
          <span>{numberValue(counts.withheld) + numberValue(counts.needs_manual_review)} held</span>
          <span>{numberValue(counts.rejected)} rejected</span>
        </div>
      ))}
    </div>
  );
}

export default async function RulesV2Page({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string; result?: string; page?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.scan) ?? freshScan();
  const result = filters.some(([value]) => value === params.result) ? params.result ?? "all" : "all";
  const query = new URLSearchParams();
  query.set("page_size", "50");
  if (result !== "all") query.set("result", result);
  if (params.page) query.set("page", params.page);
  const [summary, candidates] = await Promise.all([getRulesV2Summary(scan.id), getRulesV2Candidates(scan.id, query)]);
  const hasRules = Boolean(summary?.version);

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Rules v2</p>
          <h1><PinkDotText text="Promote evidence, not hunches." /></h1>
          <p>Candidate rules, context checks, and promotion-gate decisions for the selected folder scan.</p>
        </div>
      </section>

      <section className="rules-v2-board">
        <div className="rules-v2-score-strip">
          <span><strong>{metric(summary, "candidate_count")}</strong> candidates</span>
          <span><strong>{metric(summary, "promoted")}</strong> promoted</span>
          <span><strong>{metric(summary, "withheld")}</strong> withheld</span>
          <span><strong>{metric(summary, "needs_manual_review")}</strong> review</span>
          <span><strong>{metric(summary, "rejected")}</strong> rejected</span>
        </div>

        <div className="rules-v2-meta">
          <span className="mono">scan {scan.repository_name ?? scan.id}</span>
          <span>{hasRules ? summary?.version : "Rules v2 has not run for this scan"}</span>
          <span>{numberValue(summary?.catalog?.rule_count)} rules registered</span>
          <span>{numberValue(summary?.metrics?.repository_files_considered)} files considered</span>
        </div>

        <FamilyMatrix summary={summary} />

        <div className="rules-v2-filter-row">
          {filters.map(([value, label]) => (
            <Link className={result === value ? "is-active" : ""} href={buildQuery(scan.id, value)} key={value}>
              {label}
            </Link>
          ))}
        </div>

        <div className="rules-v2-candidate-list">
          {candidates?.items?.length ? (
            candidates.items.map((item) => (
              <CandidateRow
                candidate={item.candidate}
                decision={item.decision}
                key={item.candidate.candidate_id}
              />
            ))
          ) : (
            <div className="app-panel">
              <div className="panel-title">
                <h2>No candidates in this view</h2>
                <span className="mono muted">{result}</span>
              </div>
              <p className="muted">Run a fresh scan or change the filter to inspect Rules v2 decisions.</p>
            </div>
          )}
        </div>
      </section>
    </>
  );
}
