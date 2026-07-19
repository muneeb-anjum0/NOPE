# NOPE API Reference

Human note: this doc is meant to explain the thing plainly. If something is still limited or local-only, I would rather say that out loud than hide it behind shiny wording.


FastAPI exposes interactive OpenAPI documentation at `/docs`.

Except for sanitized `GET /health` and `POST /api/auth/login`, endpoints require a valid `Authorization: Bearer <token>` header from the local login flow.

## Core endpoints

- `GET /health` - sanitized public liveness status only.
- `GET /api/health/details` - authenticated database, scanner, AI runtime, and sandbox configuration health.
- `GET /api/projects` - list projects.
- `POST /api/projects` - create project.
- `POST /api/scans/url` - start authorized URL scan.
- `POST /api/scans/repository` - start repository ZIP scan.
- `POST /api/scans/full` - start combined repository and URL scan.
- `POST /api/scans/{scan_id}/cancel` - request cancellation for a queued or running scan.
- `POST /api/scans/{scan_id}/retry` - requeue a failed, partial, completed, or cancelled scan when its workspace is available.
- `GET /api/scans` - list scans.
- `GET /api/scans/{scan_id}` - scan detail.
- `GET /api/scans/{scan_id}/events` - persisted stage/progress and scanner-run event stream for reload-safe polling.
- `GET /api/scans/{scan_id}/findings` - server-backed findings query with filters, sorting, and pagination. Supported query parameters include `severity`, `confidence`, `status`, `scanner`, `rule`, `cwe`, `owasp`, `file`, `route`, `first_seen`, `new`, `fixed`, `reintroduced`, `suppressed`, `ai_reviewed`, `verified`, `fix_available`, `query`, `sort`, `direction`, `page`, and `page_size`.
- `GET /api/scans/{scan_id}/findings/{finding_id}` - protected finding detail with evidence, source snippet, code flow, fix/test guidance, and history.
- `POST /api/scans/{scan_id}/findings/{finding_id}/suppress` - suppress a finding with reason, scope, and optional expiry.
- `GET /api/scans/{scan_id}/artifacts/{artifact_id}` - protected raw scanner artifact payload for artifacts owned by the scan.
- `GET /api/artifacts/{artifact_id}` - protected persisted artifact metadata for artifacts owned by the authenticated user or one of their scans.
- `POST /api/scans/{scan_id}/baseline` - create a security baseline snapshot from a completed scan.
- `GET /api/baselines` - list owner-scoped baselines, optionally filtered by `project_id`.
- `GET /api/baselines/{baseline_id}` - get one owner-scoped baseline.
- `GET /api/scans/{scan_id}/compare` - compare a scan to `against_scan_id`, `baseline_id`, or the previous project scan.
- `POST /api/scans/{scan_id}/drift` - compare and persist drift events for the scan.
- `GET /api/scans/{scan_id}/drift` - list persisted drift events for the scan.
- `GET /api/scans/{scan_id}/coverage` - coverage records.
- `GET /api/scans/{scan_id}/attack-map` - attack-surface graph.
- `GET /api/queue/status` - queue depth, processing depth, worker heartbeat, and Redis health.
- `GET /api/worker/health` - worker-oriented health summary derived from Redis heartbeat state.
- `GET /api/sandbox/health` - sandbox enablement, Docker CLI availability, default network posture, limits, and isolation flags.
- `GET /api/settings/system` - owner-scoped persisted system settings for Qwen, scanners, retention, reports, artifact limits, and sandbox limits.
- `PUT /api/settings/system` - validate and save owner-scoped system settings.
- `GET /api/projects/{project_id}/settings` - owner-scoped project scan settings with sensitive test identity values redacted.
- `PUT /api/projects/{project_id}/settings` - validate and save project settings; test identity secrets are encrypted and never returned.
- `GET /api/github/status` - owner-scoped GitHub credential/connection state, blocked honestly when credentials are absent, incomplete, expired, revoked, or unverified.
- `PUT /api/github/settings` - save GitHub App/OAuth/token contract settings; client secret, private key, webhook secret, and access token are encrypted and never returned.
- `POST /api/github/connect` - create and persist a one-time OAuth state value for CSRF protection and return an authorization URL when client/callback settings exist.
- `GET /api/github/callback` - validate the stored OAuth state and record callback receipt; token exchange remains externally blocked unless credentials are supplied and verified.
- `GET /api/github/repositories` - verify stored token credentials, list owner-scoped repositories, persist repository references, and never fake repositories when access is blocked.
- `DELETE /api/github/connection` - revoke the local connection, remove repository references, and preserve an audit trail.
- `POST /api/github/scans/repository` - create a repository or full scan from a least-privilege GitHub archive download after branch/default-branch and commit SHA discovery.
- `GET /api/scans/{scan_id}/report.{format}` - protected report download as `json`, `md`, `sarif`, or `pdf`; generation persists completed status, byte size, SHA-256, and artifact metadata when object storage is reachable.
- `GET /api/scans/{scan_id}/reports/{format}/status` - protected report generation status, including `not_generated`, `running`, `completed`, or `failed`, retry attempt, byte size, SHA-256, redacted error, and artifact metadata.
- `POST /api/scans/{scan_id}/reports/{format}/retry` - protected retryable report generation using persisted scan, baseline, and drift data.
- `POST /api/retention/cleanup` - owner-scoped cleanup for scan/report/artifact/event state older than the configured or supplied retention window.
- `GET /api/scanners/capabilities` - authenticated scanner health, version, coverage category, and applicability marker metadata.
- `GET /api/settings/model` - current AI model configuration.
- `POST /api/settings/model/test` - test AI runtime reachability.
- `POST /api/scans/{scan_id}/findings/{finding_id}/ai-actions` - queue or serve a cached durable Qwen action. Supported actions are `explain`, `challenge`, `fix`, `regression_test`, and `patch_review`; `test` remains an alias for `regression_test`.
- `GET /api/ai-actions/{job_id}` - poll a durable AI action job with queued/running/completed/failed/cancelled state, cache flag, latency, context count, and structured result.
- `DELETE /api/ai-actions/{job_id}` - request cancellation for a queued or running AI action.
- `POST /api/findings/explain` and `POST /api/findings/{action}` - compatibility endpoints for direct focused AI actions.

## Guarantees

- Scanners that fail are returned as failed scanner runs.
- AI output is optional and separately marked.
- URL scans without authorization confirmation are rejected.
- Private network targets are rejected unless local sandbox mode is explicitly allowed.
- Sandbox manifests are optional; repositories without `.nope/sandbox.json` are marked not applicable instead of faked.
- Sandbox containers run with bounded CPU, memory, process, timeout, tmpfs, and log limits; repository mounts are read-only and network is disabled by default.
- Repository dynamic scans use `.nope/sandbox.json` only, support allowlisted Node/Python starts, and run ZAP against a private internal Docker-network target rather than arbitrary external hosts.
- ZAP version, baseline configuration, raw JSON alerts, parsed alerts, artifacts, and unauthenticated/partial/skipped/failed coverage states are persisted through normal scanner-run, stage, coverage, and report payloads.
- AI failures do not fail deterministic scans.
- Browser-origin state-changing requests are rejected when the `Origin` header is outside the configured web origins.
- API responses include conservative security headers and oversized requests are rejected before route handling.
- Session tokens are stored as digests and Redis-backed login failure counters are used when Redis is reachable.
- Report failures are durable, redacted, and retryable; failed or running report rows are never served as completed downloads.
- Retention cleanup is owner-scoped and removes expired scan-linked reports, artifacts, events, and drift rows through database-owned cascading state.
- Finding AI actions are owner-scoped, durable, restart-recoverable, and cached for 24 hours using finding fingerprint, action, model, quantization, prompt version, RAG version, evidence hash, and settings hash.
- Qwen receives bounded RAG context only; whole repositories and raw secrets are not persisted or sent as action context.
- Project, scan, report, settings, GitHub contract, and AI explanation routes are scoped to the authenticated local user.
- Sensitive settings are encrypted at rest and are not returned after save.
- GitHub downloads use API archive endpoints rather than embedding credentials into git remotes; tokens are never written into scan reports or remotes.
- GitHub repository policies block oversized repositories, oversized archives, excessive extracted files, submodules, and Git LFS pointer archives by default.
