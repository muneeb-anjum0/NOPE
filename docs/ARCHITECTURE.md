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
  -> Optional repository sandbox workflows
  -> Optional internal ZAP dynamic scan
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
- `nope-postgres`: local auth, project, scan, finding, coverage, stage, scanner-run, and generated report persistence.
- `nope-redis`: queue broker.
- `nope-minio`: object/artifact storage.
- `nope-ai`: optional llama.cpp server for local Qwen inference, enabled with CPU or GPU Compose profiles.

## UI architecture

- `/`: public landing page.
- `/app`: redirects to the local workspace.
- `/app/projects/local`: project overview.
- `/app/projects/local/findings`: findings and detail workflow.
- `/app/projects/local/attack-map`: attack graph canvas.
- `/app/projects/local/coverage`: coverage matrix.
- `/app/projects/local/scans`: scan launcher and history.
- `/app/projects/local/assets`: asset classes.
- `/app/projects/local/reports`: report exports.
- `/app/projects/local/settings`: scanner/model settings.

The app shell uses a route-aware LineSidebar-style icon rail and a single graphite design system.

## Storage model

The local implementation uses Postgres for local authentication and scan persistence. The migration-backed repository stores projects, scans, stages, scanner runs, findings, evidence, finding sources/history, coverage, generated report bodies, settings, baselines, drift events, artifacts, audit logs, and GitHub contract entities.

Current scan objects are also stored as JSON snapshots so the API contract remains stable while normalized tables preserve the high-value relational records used by reports, history, and status views.

## Job flow

The API validates scan requests, persists a queued `Scan`, extracts repository uploads into the shared workspace volume when needed, and enqueues Redis jobs. The worker consumes Redis jobs, runs the same scan engine, checkpoints stage progress back to Postgres, honors cancellation flags between stages, records retry/failure events, and keeps a Redis heartbeat for `/api/worker/health`.

## Sandbox flow

Repositories can opt into Phase 10 sandbox execution with `.nope/sandbox.json`. The worker launches disposable Docker containers for declared Node, Python, static, or custom commands with non-root users, dropped capabilities, `no-new-privileges`, read-only repository mounts, no sandbox Docker socket, no host home, no NOPE service secrets, bounded CPU/memory/PID/tmpfs/log limits, network disabled by default, and timeout cleanup.

For dynamic ZAP coverage, NOPE creates a private internal Docker network, starts the declared app container, runs the ZAP container against that internal target only, records bounded evidence, and tears down the containers/network.

## Evidence policy

NOPE separates evidence from reasoning:

- Deterministic scanners and custom rules create findings.
- The pipeline normalizes, deduplicates, and connects findings to evidence.
- RAG retrieves focused context only.
- AI analysis can challenge or explain findings through llama.cpp, but cannot silently downgrade scanner evidence.
- Failed scanners and failed AI are visible coverage gaps.
