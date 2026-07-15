# NOPE API Reference

FastAPI exposes interactive OpenAPI documentation at `/docs`.

Except for `GET /health` and `POST /api/auth/login`, endpoints require a valid `Authorization: Bearer <token>` header from the local login flow.

## Core endpoints

- `GET /health` - service health, version, scanner availability, AI runtime status.
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
- `GET /api/scans/{scan_id}/coverage` - coverage records.
- `GET /api/scans/{scan_id}/attack-map` - attack-surface graph.
- `GET /api/queue/status` - queue depth, processing depth, worker heartbeat, and Redis health.
- `GET /api/worker/health` - worker-oriented health summary derived from Redis heartbeat state.
- `GET /api/scans/{scan_id}/report.{format}` - export report as `json`, `md`, or `sarif`.
- `GET /api/scanners/capabilities` - authenticated scanner health, version, coverage category, and applicability marker metadata.
- `GET /api/settings/model` - current AI model configuration.
- `POST /api/settings/model/test` - test AI runtime reachability.
- `POST /api/findings/explain` - send one normalized finding to the configured llama.cpp adapter for a focused explanation.

## Guarantees

- Scanners that fail are returned as failed scanner runs.
- AI output is optional and separately marked.
- URL scans without authorization confirmation are rejected.
- Private network targets are rejected unless local sandbox mode is explicitly allowed.
- AI failures do not fail deterministic scans.
- Project, scan, report, settings, and AI explanation routes are scoped to the authenticated local user.
