# NOPE Completion Master Plan

The long-form audit trail lives in [`docs/audits/COMPLETION_MASTER_PLAN.md`](audits/COMPLETION_MASTER_PLAN.md). This file exists as the top-level stage tracker used by the stage completion prompts.

## Stage 13: Rules v2, Evidence Correlation, and Detection Intelligence

Pre-stage commit: `4f1feb546b24db632a937581c1860316f9182f9d`

Stage 13 adds a first-class Rules v2 layer between raw scanner/rule signals and promoted findings.

Implemented local scope:

- Rules v2 catalog schema with semantic versions, families, evidence requirements, promotion requirements, safe patterns, remediation, and tags.
- Existing NOPE rules upgraded into the catalog instead of being replaced.
- New framework-aware rule families for Next.js, Prisma, Supabase/RLS, auth providers, cross-evidence correlation, AI cost abuse, webhooks/OAuth, rate limits, privacy, uploads/storage, and deployment/CI.
- Candidate generation from repository text, attack-surface graph hints, and external scanner findings.
- Promotion decisions for `promoted`, `withheld`, `needs_manual_review`, and `rejected`.
- Rules v2 scan snapshot with candidates, decisions, coverage, metrics, failures, and promoted finding IDs.
- Owner-scoped API endpoints for rule inventory, Rules v2 scan summary, candidate lists, candidate filtering, and candidate detail.
- Report output for JSON, Markdown, SARIF, and PDF.
- Dashboard page for candidate review.
- Regression tests covering catalog validation, deterministic candidate identity, promotion, withholding, external scanner correlation, API authorization, pagination, and report output.

Stage 13.5 completion pass:

- Added normalized Rules v2 database tables for candidates, immutable evidence rows, correlations, promotion history, and candidate suppression state.
- Candidate APIs read normalized tables first and fall back to legacy scan snapshots so old scan history remains compatible.
- Candidate generation now builds one reusable repository context per scan: source blocks, imports, framework hints, authorization helpers, owner/tenant guards, and Supabase owner-bound RLS policy tables.
- Authorization, IDOR, Prisma, Supabase RLS, AI, upload, webhook, storage, cache, secret, and deployment candidates now carry framework/source-block metadata when available.
- Safe wrapper and RLS policy fixtures prove that strong safe-pattern evidence rejects weak candidates before they become findings.
- Stage 13.5 regression coverage includes vulnerable/safe fixtures, normalized persistence, API compatibility, promotion-gate behavior, deterministic candidate identity, and report output.

Remaining honest boundary:

- Rules v2 is production-grade for the local NOPE scope, but it is still a bounded static analysis engine, not a language-server-grade compiler for every framework in existence.

## Stage 14: Hybrid Semantic Retrieval and Repository Intelligence

Pre-stage commit: `2c72dfd`

Stage 14.1 pre-stage commit: `517d83230a7c122d5cdfd9d94fd4273a0a3aa633`

Stage 14.2 hardening pre-stage commit: `6a4adba8f647796f9ae3aa304b2d0a58c1446146`

Stage 14 adds a repository-intelligence index that supports hybrid retrieval for Qwen actions and direct repository search.

Implemented local scope:

- Repository indexing stage runs after finding promotion and before Qwen review, without changing deterministic scan success.
- Security-relevant files are chunked with symbol/configuration awareness and bounded file, byte, chunk, and token limits.
- Redacted chunk metadata, file metadata, index jobs, retrieval sessions, retrieval results, and indexing failures persist in Postgres.
- Qdrant is included in Compose as the vector store for redacted repository chunk vectors.
- Real local CPU embeddings are provided by `sentence_transformers` with `BAAI/bge-small-en-v1.5`; `local_hashing` remains explicit test/troubleshooting mode only.
- API and worker share a persistent embedding-model cache at `/app/.nope-model-cache`.
- Model download is an explicit operator command, not a hidden Docker-build or scan-time side effect.
- Embedding calls enforce batch, timeout, device, normalization, and health reporting boundaries.
- Qdrant collection dimension is checked before vector writes so incompatible indexes require reindexing instead of being reused silently.
- Retrieval combines exact file/route/symbol matches, keyword scoring, graph hints, finding-centered evidence, and vector scores when Qdrant is available.
- Qwen actions prefer the Stage 14 hybrid RAG packet and fall back to the older deterministic RAG path if an index is unavailable.
- Repository search UI and owner-scoped API endpoints expose index status and search results.
- Retrieval context includes file, line range, provenance, score reasons, retrieval reason, and untrusted-repository trust-boundary labels.
- Repository intelligence is explicitly read-only for findings: it cannot create, promote, suppress, reject, or mutate severity/confidence.
- Benchmark mode `repository-intelligence` checks retrieval Hit@3/Hit@5 against the benchmark fixture.
- Mid-index cancellation is checked during file discovery, chunking, embedding batches, vector cleanup, and vector writes so a cancelled scan can stop inside repository indexing instead of waiting for the stage to finish.
- Reindexing deletes stale Qdrant vectors for the scan before uploading the replacement chunk set, preventing old vectors from surviving after file deletion or chunk-shape changes.
- Embedding calls are guarded by a process-local concurrency semaphore plus timeout handling.
- CI now runs a repository-intelligence benchmark in explicit `local_hashing` mode, while Docker/local product verification can use the real CPU embedding provider.

Remaining honest boundary:

- The index is designed for local repository snapshots and selected-scan retrieval. It is not a full language-server database or cross-repository semantic code search product.
- GitHub CI uses the explicit `local_hashing` test mode for repository-intelligence benchmarks so CI does not download neural models. Docker/local product verification uses the real `sentence_transformers` provider.

## Stage 15: AI Investigation Engine

Pre-stage commit: `9e72cd2b4acf7dba13ea143d122be366f2a98327`

Stage 15 turns Qwen from a short explanation helper into a citation-bound investigation engine for already-promoted findings.

Implemented local scope:

- Added a durable `investigate` AI action alongside Explain, Challenge, Fix, Regression Test, and Patch Review.
- Investigation reports cover root cause, evidence, repository context, attack flow, trust boundary, exploitability, prerequisites, impact, promotion rationale, confidence explanation, fix guidance, verification steps, false-positive considerations, related findings, related files/routes, database/policy/auth/middleware/storage notes, framework notes, unknowns, AI reasoning notes, and evidence references.
- Every investigation statement is normalized as Verified, Supported, Likely, Possible, or Unknown with deterministic citation IDs.
- Related-finding discovery links findings that share files, folders, routes, categories, packages, advisories, scanner sources, auth helpers, middleware, ORM models, policies, storage buckets, owner helpers, or API groups. These links are investigation leads only and never become new findings.
- Investigation reports support audience modes for Security Engineer, Developer, Executive, Junior Developer, and Compliance. The requested mode is enforced by NOPE even if Qwen returns a different mode.
- Attack-flow reconstruction is deterministic and includes request, handler/file, middleware, auth/session, authorization/policy, business logic, data/storage, response, and Rules v2 authority steps when evidence exists.
- Malformed Qwen output falls back to a deterministic investigation report instead of failing the UI or inventing evidence.
- Investigation jobs use the existing durable AI job/cache tables, so history stores prompt version, RAG version, model, quantization, evidence hash, settings hash, timestamps, latency, result, and context metadata.
- Investigation exports are protected and support JSON, Markdown, PDF, and SARIF enrichment.
- The dashboard has a dedicated Investigations page and the Findings AI action panel can render the full report with mode controls, regeneration, exports, timeline, evidence tree, attack flow, relationship leads, citations, cache state, and failed-state feedback.
- Benchmark mode `investigation` validates generated reports, citation coverage, JSON structure, export formats, deterministic attack reconstruction, relationship discovery, and fallback frequency.

Explicit boundary:

- Rules v2 decision-making was not modified. AI still cannot create findings, promote withheld candidates, suppress findings, change severity, or change confidence.
