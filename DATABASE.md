# NOPE Database

NOPE uses PostgreSQL for local authentication and, as of Phase 1, durable scan persistence.

## Migration Runner

Migrations are SQL files in `apps/api/migrations`.

At API startup, `nope_api.db.run_migrations()` creates `schema_migrations` and applies any unapplied SQL files in lexical order. Applied migration filenames are recorded by stem, for example `0001_initial`.

The runner is intentionally small and local-first. It does not drop data on startup.

## Phase 1 Schema

The initial migration creates tables for:

- Local auth: `local_users`, `local_sessions`
- Projects and repository metadata: `projects`, `project_targets`, `repository_sources`, `repository_snapshots`
- Scans: `scans`, `scan_stages`, `scanner_runs`, `scan_coverage`
- Findings: `findings`, `finding_evidence`, `finding_sources`, `finding_history`
- Reports: `reports`
- Settings placeholders: `model_configurations`, `scanner_configurations`, `application_settings`
- History/drift placeholders: `security_baselines`, `drift_events`
- Artifacts/logging: `uploaded_artifacts`, `job_artifacts`, `audit_logs`
- GitHub contracts: `github_connections`, `github_installations`, `github_repository_references`

The `scans` table stores both normalized fields and a JSON snapshot of the current API scan model. This keeps the dashboard/API stable while later phases deepen the normalized schema.

## Current Limits

- Scan execution is still synchronous until Phase 2 adds Redis-backed queued jobs.
- Raw scanner outputs and report bodies are not stored in MinIO yet.
- Direct unauthenticated API access remains available for local development compatibility; dashboard-originated calls forward the local session token and are scoped to the authenticated user.
