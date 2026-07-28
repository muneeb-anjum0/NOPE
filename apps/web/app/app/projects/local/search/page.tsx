import Link from "next/link";
import { PinkDotText } from "@/components/pink-dot-text";
import { getActiveProjectId, scansForProject } from "@/lib/active-project";
import { getProjects, getRepositoryIndexStatus, getScans, repositorySearch, selectScan } from "@/lib/nope-data";
import type { RepositorySearchResult } from "@/lib/types";

function badge(source: string) {
  return <span className="source-badge" key={source}>{source}</span>;
}

function Citation({ result }: { result: RepositorySearchResult }) {
  return (
    <code>
      {result.relative_path}:{result.start_line}-{result.end_line}
      {result.symbol_name ? ` / ${result.symbol_name}` : ""}
    </code>
  );
}

function ScoreBreakdown({ result }: { result: RepositorySearchResult }) {
  return (
    <details className="score-breakdown">
      <summary>score</summary>
      <div>
        {Object.entries(result.score_reasons).map(([key, value]) => (
          <span key={key}><strong>{key}</strong>{Number(value).toFixed(2)}</span>
        ))}
      </div>
    </details>
  );
}

export default async function RepositorySearchPage({
  searchParams,
}: {
  searchParams?: Promise<{ scan?: string; q?: string }>;
}) {
  const params = (await searchParams) ?? {};
  const [projects, allScans] = await Promise.all([getProjects(), getScans()]);
  const activeProjectId = await getActiveProjectId(projects);
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const scans = scansForProject(allScans, activeProjectId);
  const scan = selectScan(scans, params.scan);
  const query = (params.q ?? "").trim();
  const [indexStatus, search] = scan
    ? await Promise.all([getRepositoryIndexStatus(scan.id), query ? repositorySearch(scan.id, query) : Promise.resolve(null)])
    : [null, null];

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Repository Search</p>
          <h1><PinkDotText text="Ask the indexed codebase." /></h1>
          <p>
            Hybrid retrieval combines exact symbols, keywords, graph context, and local vectors. It does not create or change findings.
          </p>
        </div>
        {activeProject ? (
          <Link className="button ghost" href={`/app/projects/local/scans/${encodeURIComponent(activeProject.id)}`}>
            Open folder
          </Link>
        ) : null}
      </section>

      <section className="app-panel repository-search-panel">
        <form className="repository-search-form" action="/app/projects/local/search">
          {scan ? <input name="scan" type="hidden" value={scan.id} /> : null}
          <input
            aria-label="Repository search query"
            className="input-shell"
            name="q"
            placeholder="Find owner checks, Supabase policies, upload handlers..."
            defaultValue={query}
          />
          <button className="button" type="submit">Search</button>
        </form>
        <div className="repository-index-strip">
          <span><strong>{indexStatus?.status?.status ?? "not indexed"}</strong> index</span>
          <span>{indexStatus?.status?.files_indexed ?? 0} files</span>
          <span>{indexStatus?.status?.chunks_generated ?? 0} chunks</span>
          <span>{String((indexStatus?.vector_store as { status?: string } | undefined)?.status ?? "unknown")} vector store</span>
          <span>{String((indexStatus?.embedding as { device?: string } | undefined)?.device ?? "cpu")} embeddings</span>
        </div>
      </section>

      <section className="repository-results">
        {!scan ? (
          <div className="app-panel"><p className="muted">Run a folder scan before searching repository intelligence.</p></div>
        ) : !query ? (
          <div className="app-panel"><p className="muted">Search for a route, function, package, policy, or security concept.</p></div>
        ) : !search?.results?.length ? (
          <div className="app-panel"><p className="muted">No context matched this query. Try a file path, symbol, route, or security term.</p></div>
        ) : (
          search.results.map((result) => (
            <article className="repository-result-card" key={result.chunk_id}>
              <div className="repository-result-head">
                <div>
                  <Citation result={result} />
                  <p>{result.retrieval_reason}</p>
                </div>
                <strong>{Math.round(result.score * 100)}%</strong>
              </div>
              <div className="source-badge-row">{result.sources.map(badge)}</div>
              <pre>{result.text}</pre>
              <ScoreBreakdown result={result} />
            </article>
          ))
        )}
      </section>
    </>
  );
}
