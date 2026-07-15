# NOPE API Reference

FastAPI exposes interactive OpenAPI documentation at `/docs`.

Except for `GET /health` and `POST /api/auth/login`, endpoints require a valid `Authorization: Bearer <token>` header from the local login flow.

## Core endpoints

- `GET /health` - service health, version, scanner availability, AI runtime status, and sandbox configuration health.
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
- `GET /api/github/status` - local GitHub credential/contract state, blocked honestly when credentials are absent or unverified.
- `PUT /api/github/settings` - save GitHub App/OAuth contract settings; OAuth/private-key/webhook secrets are encrypted and never returned.
- `GET /api/github/repositories` - returns no repositories while private GitHub access is blocked; never fakes private access.
- `GET /api/github/callback` - callback route placeholder that returns blocked state until real credentials are supplied and verified.
- `GET /api/scans/{scan_id}/report.{format}` - protected report download as `json`, `md`, `sarif`, or `pdf`; PDF generation persists report status and MinIO artifact metadata when object storage is reachable.
- `GET /api/scans/{scan_id}/reports/{format}/status` - protected report generation status, byte size, SHA-256, and artifact metadata.
- `GET /api/scanners/capabilities` - authenticated scanner health, version, coverage category, and applicability marker metadata.
- `GET /api/settings/model` - current AI model configuration.
- `POST /api/settings/model/test` - test AI runtime reachability.
- `POST /api/findings/explain` - send one normalized finding to the configured llama.cpp adapter for a focused explanation.

## Guarantees

- Scanners that fail are returned as failed scanner runs.
- AI output is optional and separately marked.
- URL scans without authorization confirmation are rejected.
- Private network targets are rejected unless local sandbox mode is explicitly allowed.
- Sandbox manifests are optional; repositories without `.nope/sandbox.json` are marked not applicable instead of faked.
- Sandbox containers run with bounded CPU, memory, process, timeout, tmpfs, and log limits; repository mounts are read-only and network is disabled by default.
- AI failures do not fail deterministic scans.
- Project, scan, report, settings, GitHub contract, and AI explanation routes are scoped to the authenticated local user.
- Sensitive settings are encrypted at rest and are not returned after save.
