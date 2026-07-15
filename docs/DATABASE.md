# NOPE Database

NOPE uses PostgreSQL for local authentication and, as of Phase 1, durable scan persistence.

## Migration Runner

Migrations are SQL files in `apps/api/migrations`.

At API startup, `nope_api.db.run_migrations()` creates `schema_migrations` and applies any unapplied SQL files in lexical order. Applied migration filenames are recorded by stem, for example `0001_initial`.

The runner is intentionally small and local-first. It does not drop data on startup. `GET /health` also exposes migration status with available, applied, pending, and unexpected versions.

## Phase 1 Schema

The initial migration creates tables for:

- Local auth: `local_users`, `local_sessions`
- Projects and repository metadata: `projects`, `project_targets`, `repository_sources`, `repository_snapshots`
- Scans: `scans`, `scan_stages`, `scanner_runs`, `scan_coverage`
- Findings: `findings`, `finding_evidence`, `finding_sources`, `finding_history`
- Reports: `reports`, including generated body, SHA-256 hash, byte size, media type, and generation timestamp
- Settings placeholders: `model_configurations`, `scanner_configurations`, `application_settings`
- History/drift placeholders: `security_baselines`, `drift_events`
- Artifacts/logging: `uploaded_artifacts`, `job_artifacts`, `audit_logs`
- GitHub contracts: `github_connections`, `github_installations`, `github_repository_references`

The `scans` table stores both normalized fields and a JSON snapshot of the current API scan model. This keeps the dashboard/API stable while later phases deepen the normalized schema.

## Completion Notes

- Protected API routes require a valid local bearer token by default through `NOPE_REQUIRE_AUTHENTICATED_API=true`.
- Dashboard-originated calls forward the HttpOnly local session token and are scoped to the authenticated user.
- Scan execution is still synchronous until a later worker phase adds Redis-backed queued jobs.
- Generated report payloads are stored in Postgres.
- Raw scanner stdout/stderr artifacts are stored in MinIO and linked through `uploaded_artifacts`, `job_artifacts`, and `scanner_runs.raw_artifact_id`.
