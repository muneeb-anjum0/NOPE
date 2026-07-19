# NOPE Database

NOPE uses PostgreSQL for local authentication and durable scan persistence.

## Migration Runners

Migrations are SQL files in `apps/api/migrations` and also have Alembic revision wrappers in `apps/api/alembic/versions`.

At API startup, `nope_api.db.run_migrations()` creates `schema_migrations` and applies any unapplied SQL files in lexical order. Applied migration filenames are recorded by stem, for example `0001_initial`.

The startup runner is intentionally small and local-first. It does not drop data on startup. Public `GET /health` is sanitized; authenticated `GET /api/health/details` exposes migration status with available, applied, pending, and unexpected versions.

Alembic is available for explicit migration verification and downgrade/re-upgrade checks:

```bash
alembic -c apps/api/alembic.ini upgrade head
alembic -c apps/api/alembic.ini current
alembic -c apps/api/alembic.ini downgrade 0001_initial
alembic -c apps/api/alembic.ini upgrade head
```

Use a disposable database for downgrade checks. The `0001_initial` downgrade drops the initial NOPE tables and is destructive by design.

## Core Schema

The initial migration creates tables for:

- Local auth: `local_users`, `local_sessions`
- Projects and repository metadata: `projects`, `project_targets`, `repository_sources`, `repository_snapshots`
- Scans: `scans`, `scan_stages`, `scanner_runs`, `scan_coverage`
- Findings: `findings`, `finding_evidence`, `finding_sources`, `finding_history`
- Reports: `reports`, including generated body, SHA-256 hash, byte size, media type, generation status metadata, and generation timestamp
- Rules v2: `rules_v2_candidates`, `rules_v2_candidate_evidence`, `rules_v2_candidate_correlations`, `rules_v2_promotion_history`, and `rules_v2_candidate_suppressions`
- Settings: `model_configurations`, `scanner_configurations`, `application_settings`; owner-scoped system/project settings live in `application_settings`, with sensitive values encrypted inside JSONB envelopes.
- History/drift foundation: `security_baselines`, `drift_events`
- Artifacts/logging: `uploaded_artifacts`, `job_artifacts`, `audit_logs`
- GitHub contracts: `github_connections`, `github_installations`, `github_repository_references`; encrypted GitHub App/OAuth/token credentials live in `github_connections.data`, verified repository references are persisted, and external private access stays blocked until real credentials are verified.

The `scans` table stores both normalized fields and a JSON snapshot of the current API scan model. This keeps the dashboard/API stable while normalized tables preserve the records that need efficient querying.

Rules v2 keeps the scan JSON snapshot as a compatibility/export artifact, but candidate review is now normalized. Candidate rows, evidence, correlations, promotion history, and candidate suppression state have first-class tables. Existing APIs read those tables first and fall back to the scan snapshot for old scans. Promoted candidates also become normal `findings` rows with Rules v2 metadata preserved.

## Completion Notes

- Protected API routes require a valid local bearer token by default through `NOPE_REQUIRE_AUTHENTICATED_API=true`.
- Dashboard-originated calls forward the HttpOnly local session token and are scoped to the authenticated user.
- Scan execution is Redis-backed, but Postgres is authoritative for history: API requests persist queued scans, workers checkpoint scan snapshots, and every important scan/stage/scanner/retry/cancellation/worker/report/Qwen transition is also stored in `scan_events` with a deterministic per-scan sequence number.
- Rules v2 candidate review state is persisted through normalized tables, with scan-snapshot fallback for older data, and protected by the same owner-scoped scan access controls.
- The event stream supports idempotent insertion through `(scan_id, idempotency_key)`, ordered replay through `(scan_id, sequence)`, and incremental pagination by `after_sequence`.
- Generated report payloads are stored in Postgres. PDF bodies are base64-backed in Postgres and, when MinIO is reachable, also stored as binary report artifacts with object metadata recorded in `reports.data`.
- Raw scanner stdout/stderr artifacts and PDF report artifacts are stored in MinIO and linked through `uploaded_artifacts`, `job_artifacts`, scanner runs, and report metadata.
- Project creation now creates target/source metadata rows when target URL or repository metadata is supplied.
- Scan saves upsert repository snapshot rows when repository branch, commit, or upload metadata is present.
- Application setting, model configuration, scanner configuration, baseline, drift-event, and audit-log rows have repository-layer persistence methods and tests.
- Settings routes persist owner-scoped system/project settings, record audit rows, encrypt test identity and GitHub secret material with `NOPE_ENCRYPTION_KEY`, and return only credential/configured state after save.
