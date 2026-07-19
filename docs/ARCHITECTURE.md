# NOPE Architecture

NOPE is a rules-first security review workbench. The local app is structured as a monorepo:

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
  -> Optional internal ZAP dynamic baseline scan
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

The local implementation uses Postgres for local authentication and scan persistence. The migration-backed repository stores projects, scans, stages, scanner runs, findings, evidence, finding sources/history, coverage, generated report bodies and report generation state, settings, baselines, drift events, artifacts, audit logs, durable Qwen jobs/cache, and GitHub contract entities.

Current scan objects are also stored as JSON snapshots so the API contract remains stable while normalized tables preserve the high-value relational records used by reports, history, and status views.

## Finding lifecycle

Promoted findings use a stable NOPE fingerprint for recurrence, drift, and deduplication while preserving the original scanner fingerprint and source metadata in the finding payload. Duplicate evidence from static scanners, dependency scanners, dynamic checks, custom rules, graph hints, Qwen review, and tests is merged into one finding without dropping scanner sources or evidence rows.

Lifecycle updates are persisted through `finding_lifecycle_events`, `finding_history`, and `audit_logs`. Valid states are `new`, `confirmed`, `fixing`, `fixed`, `verified`, `false_positive`, `accepted_risk`, `suppressed`, `reopened`, and `reintroduced`. Updates are owner-scoped and optimistic-versioned through `lifecycle_version`.

Suppressions require a reason, actor, timestamp, scope, and optional expiry. Expired suppressions reopen automatically when the scan/finding is read. A finding is marked reintroduced when the same stable fingerprint appears again in the same project after a prior fixed or verified lifecycle state.

## Job flow

The API validates scan requests, persists a queued `Scan`, extracts repository uploads into the shared workspace volume when needed, and enqueues Redis jobs. The worker consumes Redis jobs, runs the same scan engine, checkpoints stage progress back to Postgres, honors cancellation flags between stages, records retry/failure events, and keeps a Redis heartbeat for `/api/worker/health`. The worker runs non-root and does not mount the Docker socket.

## GitHub flow

The GitHub integration uses the existing `github_connections`, `github_installations`, and `github_repository_references` tables. App/OAuth contract values and access tokens are stored only as encrypted envelopes in Postgres JSONB. `/api/github/connect` creates a one-time OAuth state value for CSRF protection, `/api/github/callback` validates that state, and `/api/github/repositories` is authoritative for activation: if the configured token cannot list repositories, the connection remains blocked or revoked rather than inventing access.

Repository scans from GitHub use least-privilege API calls: NOPE reads repository metadata, determines the requested or default branch, captures the commit SHA, downloads the GitHub archive endpoint, extracts it through the hardened ZIP ingestion path, enforces size, file-count, submodule, and LFS policies, creates a repository source/snapshot, and then queues the normal scan pipeline. Credentials are never written into git remotes, scan snapshots, logs, or reports. Real github.com private access is verified only when the operator supplies real credentials; local tests use a dependency-injected fake GitHub HTTP service.

## Sandbox flow

Repositories can opt into sandbox execution with `.nope/sandbox.json`. The worker delegates those requests to the internal `nope-runner` service, the only Compose service with Docker socket access. The runner accepts only token-authenticated requests for workspaces under `NOPE_TEMP_ROOT`, then launches disposable Docker containers for allowlisted Node, Python, static, or ZAP commands with non-root users, dropped capabilities, `no-new-privileges`, read-only repository mounts, no sandbox Docker socket, no host home, no NOPE service secrets, bounded CPU/memory/PID/tmpfs/log limits, network disabled for normal workflows, and timeout cleanup.

For dynamic ZAP coverage, NOPE supports manifest-declared Node and Python application starts. The runner executes allowlisted build/workflow commands first, starts the declared application container, waits for readiness from inside a private internal Docker network, runs OWASP ZAP baseline against that internal target only, captures ZAP version/config/raw JSON alerts, normalizes parsed alerts into findings, and tears down the containers/network. If build, startup, readiness, ZAP, or authentication state is incomplete, coverage is marked skipped, partial, or failed rather than completed.

## Evidence policy

NOPE separates evidence from reasoning:

- Deterministic scanners and custom rules create findings.
- The pipeline normalizes, deduplicates, and connects findings to evidence.
- RAG retrieves focused context only.
- AI analysis can challenge or explain findings through llama.cpp, but cannot silently downgrade scanner evidence.
- Failed scanners and failed AI are visible coverage gaps.
