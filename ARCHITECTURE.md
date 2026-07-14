# NOPE Architecture

NOPE is a rules-first, evidence-driven application security orchestration platform. The local MVP is structured as a monorepo:

```text
apps/
  api/       FastAPI orchestration API
  web/       Next.js dashboard
  worker/    Python worker entrypoint for queued scans
packages/
  shared/    Shared TypeScript contracts for the UI
security-packs/
  nope-core-rules.json
tests/
  fixtures/ vulnerable sample repositories
docker/
  api.Dockerfile
  web.Dockerfile
```

## Data flow

```text
Repository ZIP / Authorized URL
  -> Ingestion and scope validation
  -> Secure workspace extraction
  -> Stack detection
  -> Attack-surface and code graph builders
  -> Scanner plugin orchestrator
  -> NOPE rules engine
  -> Finding normalization and deduplication
  -> Focused retrieval
  -> Optional AI reasoning
  -> Coverage, reports, drift metadata
  -> Dashboard/API exports
```

## Runtime services

- `nope-web`: Next.js UI. In Docker this is the primary container named `NOPE`.
- `nope-api`: FastAPI backend and scan orchestration.
- `nope-worker`: worker process for queue-oriented scan execution.
- `nope-postgres`: planned persistent database.
- `nope-redis`: queue broker.
- `nope-minio`: object/artifact storage.
- Optional AI runtime: configured by URL, not bundled.

## Storage model

The initial local implementation uses an in-memory repository so scans work without infrastructure. The API models are intentionally database-ready: projects, scan requests, findings, coverage records, code graph nodes/edges, scanner runs, and reports all have stable IDs and serializable contracts.

## Job flow

The API exposes a synchronous development scan path and the worker exposes the same scan engine for queued execution. Redis/Celery-ready configuration is included, but durable job orchestration is marked partial until production persistence is added.

## Evidence policy

NOPE separates evidence from reasoning:

- Deterministic scanners and custom rules create findings.
- The pipeline normalizes, deduplicates, and connects findings to evidence.
- RAG retrieves focused context only.
- AI analysis can challenge or explain findings, but cannot silently downgrade scanner evidence.
- Failed scanners and failed AI are visible coverage gaps.
