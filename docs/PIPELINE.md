# NOPE Pipeline

Human note: this doc is meant to explain the thing plainly. If something is still limited or local-only, I would rather say that out loud than hide it behind shiny wording.


This is the path a scan takes through NOPE. I wrote it down because a security tool that cannot explain its own pipeline is hard to trust.

## 1. Authentication

Users log in through `/login`. The first successful login creates a local Postgres user, stores a PBKDF2 password hash, creates a session token, and sets the `nope_session` HttpOnly cookie through the web route. Protected API calls use `Authorization: Bearer <token>`.

## 2. Project and Scope

The dashboard works with the local workspace project. Project settings can store target URL, approved hosts, excluded paths, scan depth, test identities, baseline policy, repository metadata, and RAG limits. Sensitive test identity values are encrypted and never returned after save.

URL scans require explicit authorization confirmation. Private network and localhost targets are blocked unless the local/sandbox settings explicitly allow them.

## 3. Scan Creation

The API creates a durable `Scan` row and JSON snapshot, initializes stage records, extracts uploaded ZIPs into the shared workspace volume when needed, and enqueues a Redis job. The API returns before long scan work completes.

Supported modes:

- URL-only
- Repository-only
- Full repository plus URL

## 4. Queue and Worker

Redis stores queued jobs, active-scan locks, cancellation flags, processing jobs, retry metadata, and worker heartbeat. The worker consumes jobs, checkpoints scan snapshots and stage progress to Postgres, honors cancellation between stages, retries bounded failures with backoff, and exposes queue/worker health through API endpoints.

Durable progress does not depend on Redis or the browser staying connected. The `scan_events` table records ordered, idempotent events for scan creation, queueing, preparation, stage transitions, scanner starts/completions/failures/timeouts/unavailable states, retries, cancellation request/acknowledgement, worker heartbeat/lost recovery, Qwen start/completion/failure, report generation, and terminal scan states. `/api/scans/{scan_id}/events` replays that table with `after_sequence` and `limit`, so frontend polling is only a transport layer.

## 5. Repository Analysis

Repository scans perform:

- Stack detection
- Attack-surface extraction
- Lightweight code graph creation
- NOPE deterministic rules
- External scanner applicability checks
- Scanner execution and parser normalization
- Optional sandbox workflows
- Focused RAG retrieval
- Optional Qwen review

Scanner failures are persisted as failed scanner runs and reduce coverage honestly.

## 6. Dynamic and Sandbox Analysis

If `.nope/sandbox.json` is present, the socketless worker asks the internal `nope-runner` service to execute constrained Docker workflows for the already-extracted workspace. Repository workflow containers run with non-root users, no privileged mode, no Docker socket, no host home, no NOPE service secrets, dropped capabilities, `no-new-privileges`, bounded CPU/memory/PID/tmpfs/logs, allowlisted images and commands, no arbitrary mounts/env/networks, network disabled, and timeout cleanup.

If ZAP is enabled in the manifest, NOPE creates a private internal Docker network, starts the declared app container, runs the ZAP baseline container against that internal target, records bounded evidence, and tears everything down.

## 7. URL Checks

URL checks are non-destructive. They inspect headers, cookies, exposed paths, CORS, redirects, and scope behavior. URL-only scans clearly record that source code and authenticated runtime paths were not inspected.

## 8. Findings

Findings are normalized into one shared model with scanner, original rule, NOPE rule, severity, original severity, confidence, CWE, OWASP, file, line, route, package, CVE, evidence, raw artifact, remediation, lifecycle, baseline, recurrence, and suppression fields.

Deduplication merges repeated evidence for the same issue while preserving scanner/custom/dynamic evidence.

## 9. Focused RAG and Qwen

RAG retrieves bounded, provenance-carrying context around findings, routes, files, finding-centered graph neighbors, scanner evidence, and security guidance. Repository text is treated as untrusted data.

Qwen is optional and runs through `nope-ai` llama.cpp. It receives focused evidence only, not whole repositories, and cannot silently downgrade deterministic findings. Finding actions are durable jobs for Explain, Challenge, Fix, Regression Test, and Patch Review. Completed action output is cached for 24 hours and invalidates when evidence, settings, prompt version, RAG version, model, or quantization changes. If Qwen fails, deterministic scans continue and AI coverage records the failure.

## 10. Coverage, Score, and Verdict

Coverage records distinguish verified, partial, failed, and not-tested areas. Scores and verdicts are derived from findings and coverage gaps. NOPE avoids all-clear language; untested areas remain visible.

## 11. Reports, Baselines, and Drift

Report formats:

- JSON
- Markdown
- SARIF
- PDF

Report bodies are persisted in Postgres. PDF artifacts are also stored in MinIO when object storage is reachable.
Report generation status is durable as `running`, `completed`, or `failed`; failed rows keep redacted error and attempt metadata and can be retried without serving stale bodies as completed downloads.

Baselines snapshot scan, repository, target, scanner, rule, model, RAG, coverage, finding, route, dependency, and stack metadata. Drift compares latest vs previous, latest vs baseline, or arbitrary scan vs scan, and persists drift events for new, fixed, recurring, reintroduced, severity-changed, confidence-changed, route, dependency, CVE, secret, RLS, CORS, header, tracker, public asset, scanner-coverage, scanner-version, rule-version, model-version, and RAG-version changes. Incremental-scan data remains conservative and advisory; persisted full-scan evidence remains authoritative.

## 12. UI

The landing page lives at `/`. The dashboard lives under `/app/projects/local/*` with routes for overview, findings, attack map, coverage, scans, assets, reports, and settings. Browser checks cover desktop, tablet, and small mobile widths.
