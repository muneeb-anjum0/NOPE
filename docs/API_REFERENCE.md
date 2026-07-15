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
- `GET /api/scans` - list scans.
- `GET /api/scans/{scan_id}` - scan detail.
- `GET /api/scans/{scan_id}/findings` - normalized findings.
- `GET /api/scans/{scan_id}/coverage` - coverage records.
- `GET /api/scans/{scan_id}/attack-map` - attack-surface graph.
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
