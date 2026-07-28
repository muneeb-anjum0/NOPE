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

Stage 14 adds a repository-intelligence index that supports hybrid retrieval for Qwen actions and direct repository search.

Implemented local scope:

- Repository indexing stage runs after finding promotion and before Qwen review, without changing deterministic scan success.
- Security-relevant files are chunked with symbol/configuration awareness and bounded file, byte, chunk, and token limits.
- Redacted chunk metadata, file metadata, index jobs, retrieval sessions, retrieval results, and indexing failures persist in Postgres.
- Qdrant is included in Compose as the vector store for redacted repository chunk vectors.
- Retrieval combines exact file/route/symbol matches, keyword scoring, graph hints, finding-centered evidence, and vector scores when Qdrant is available.
- Qwen actions prefer the Stage 14 hybrid RAG packet and fall back to the older deterministic RAG path if an index is unavailable.
- Repository search UI and owner-scoped API endpoints expose index status and search results.
- Retrieval context includes file, line range, provenance, score reasons, retrieval reason, and untrusted-repository trust-boundary labels.
- Repository intelligence is explicitly read-only for findings: it cannot create, promote, suppress, reject, or mutate severity/confidence.
- Benchmark mode `repository-intelligence` checks retrieval Hit@3/Hit@5 against the benchmark fixture.

Remaining honest boundary:

- The default local embedding provider is deterministic CPU hashing so the stack is self-contained and fast in CI. A `sentence_transformers` provider hook exists for BGE-style embeddings when the operator installs the dependency/model, but the local verified path does not download or require that neural model.
- The index is designed for local repository snapshots and selected-scan retrieval. It is not a full language-server database or cross-repository semantic code search product.
