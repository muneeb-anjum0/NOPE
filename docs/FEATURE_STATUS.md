# NOPE Feature Status

Status values are limited to: Complete, Partially complete, Not implemented, Blocked by external dependency, Not applicable.

This matrix was rebuilt during the original Phase 0 on 2026-07-15 and refreshed by the canonical Phase 0 recovery audit on 2026-07-15 from repository evidence, Git history, documentation, implementation files, and the current working tree. A feature is marked Complete only when it is implemented, wired into the real path, exercised, and verified.

Canonical Phase 0 note: current `HEAD` was `194a1e8` (`feat(phase-2): complete scanner execution pipeline`) when recovery began. Phase 3 queue/worker WIP has since been completed, verified, and committed through the canonical phase gate.

| Feature | Current status | Evidence | Relevant files | Missing work | Verification method | External dependency status |
| --- | --- | --- | --- | --- | --- | --- |
| Local authentication | Complete | Local accounts/sessions are stored in Postgres and dashboard routes require a session. | `apps/api/nope_api/auth.py`, `apps/api/nope_api/main.py`, `apps/web/lib/auth.ts`, `apps/web/app/login/page.tsx` | Password reset, org auth, CSRF hardening, production identity provider. | Login smoke tests, Docker health, `GET /api/auth/me`. | None for local mode. |
| User persistence | Complete | `local_users` table is created by migrations and reused across logins. | `apps/api/nope_api/auth.py`, `apps/api/migrations/0001_initial.sql` | Password reset and org identity providers are later SaaS features. | Local login through web/API. | None. |
| Project persistence | Complete | Projects persist in Postgres with owner scoping, supporting target/source/snapshot tables, and authenticated API access. | `apps/api/nope_api/storage.py`, `apps/api/nope_api/main.py`, `apps/api/migrations/0001_initial.sql` | None for Phase 1 local persistence scope. | Persistence tests, authenticated API tests, Docker migration smoke. | None. |
| Scan persistence | Complete | Scans persist in Postgres JSON snapshots and normalized scan rows; worker progress, stage history, retry/cancel events, scanner runs, and findings survive API restart. | `apps/api/nope_api/storage.py`, `apps/api/migrations/0001_initial.sql`, `apps/api/nope_api/queue.py` | Later history phases can add richer attempt tables. | API restart smoke; Phase 3 queued scan `scan_4ebe1b771ac7413b` completed after API restart. | None. |
| Finding persistence | Complete | Findings, evidence, scanner sources, and history rows are written for persisted scans. | `apps/api/nope_api/storage.py`, `apps/api/migrations/0001_initial.sql` | Suppression workflow remains unimplemented. | Persistence tests and table-count smoke. | None. |
| Scanner-run persistence | Complete | Scanner runs persist version/status/coverage/messages/counts, command, exit code, bounded redacted output, and raw artifact links. | `apps/api/nope_api/storage.py`, `apps/api/nope_api/models.py`, `apps/api/migrations/0001_initial.sql` | Authorized artifact download API can be added later for UI convenience. | Backend tests, DB artifact join smoke for `scan_e1b6a69758a848bd`. | None. |
| Scan-stage persistence | Complete | Scan stages persist as ordered rows with name/status/data; worker checkpoints make stage progress reload-safe. | `apps/api/nope_api/storage.py`, `apps/api/migrations/0001_initial.sql`, `apps/api/nope_api/scan_engine.py` | Later observability can add separate metrics tables. | Backend tests and Docker scan event proof. | None. |
| Redis queue | Complete | API enqueues Redis jobs with job IDs, active scan idempotency, retry metadata, bounded backoff, processing tracking, stuck-job requeue support, and queue health. | `apps/api/nope_api/queue.py`, `apps/api/nope_api/main.py`, `apps/api/requirements.txt` | Production queue dashboards/concurrency controls are later polish. | Docker queued scans `scan_4ebe1b771ac7413b`, `scan_c8fbd2708e4044e6`; `/api/queue/status`; Redis outage simulation. | None. |
| Worker consumption | Complete | `nope-worker` consumes Redis jobs, checkpoints progress, persists findings, emits heartbeat, survives Redis loop failures, and uses the shared workspace volume. | `apps/worker/worker.py`, `apps/api/nope_api/queue.py`, `docker-compose.yml`, `docker/api.Dockerfile` | Dedicated worker metrics can be added later. | Docker worker completed queued repository scan with 29 findings; worker heartbeat verified after Redis restart. | None. |
| Retry behavior | Complete | Retry endpoint clears cancellation flags, requeues with force, queue helper tracks attempts/max attempts and bounded backoff, and failed-attempt events are persisted. | `apps/api/nope_api/main.py`, `apps/api/nope_api/queue.py`, `apps/api/tests/test_queue.py` | Attempt analytics UI belongs to later history work. | Failed scan `scan_phase3_retry_failed` retried through API and completed with 29 findings. | None. |
| Cancellation | Complete | Cancel endpoint sets Redis cancellation flag and persists cancellation stages; worker checks cancellation before work and between scan-engine checkpoints. | `apps/api/nope_api/main.py`, `apps/api/nope_api/queue.py`, `apps/api/nope_api/scan_engine.py` | UI cancel controls can be polished later. | Queued scan `scan_c8fbd2708e4044e6` cancelled and stayed cancelled with persisted events. | None. |
| ZIP ingestion | Complete | ZIP uploads extract to bounded temp workspace; size/file count/path traversal/symlink checks exist and UI upload smoke test completed. | `apps/api/nope_api/ingestion.py`, `apps/web/components/scan-launcher.tsx`, `apps/web/app/api/start-scan/route.ts` | Persist uploaded artifact metadata and cleanup records. | `python -m pytest`; UI `/api/start-scan` ZIP smoke test. | None. |
| URL scanning | Partially complete | Authorized URL endpoint performs non-destructive HTTP checks and blocks private/localhost by default. | `apps/api/nope_api/url_scanner.py`, `apps/api/nope_api/security.py`, `apps/api/nope_api/main.py` | TLS depth, browser crawl, privacy tracker detection, ZAP baseline, authenticated dynamic paths. | URL scope tests and API health. | ZAP/browser tooling not integrated yet. |
| Full scan | Partially complete | Full endpoint validates URL scope, extracts repository uploads, enqueues the worker job, and combines repository/URL scan engine paths. | `apps/api/nope_api/main.py`, `apps/api/nope_api/scan_engine.py`, `apps/api/nope_api/queue.py` | Sandbox execution, dynamic testing, authenticated test accounts. | API code audit, backend tests, Docker queue verification. | None for local contracts. |
| Stack detection | Partially complete | Heuristic detector identifies common languages/frameworks/data systems from files/manifests. | `apps/api/nope_api/stack_detector.py` | Expand ecosystem coverage, parser-backed evidence, more fixtures. | `python -m pytest`, ZIP smoke scan. | None. |
| Attack-surface extraction | Partially complete | Heuristic extraction maps common API routes and risky hints. | `apps/api/nope_api/attack_surface.py` | Detailed method/handler/middleware/auth/tenant extraction across frameworks. | `python -m pytest`, code audit. | None. |
| Code graph | Partially complete | Lightweight route/file/auth/risk graph is generated from attack-surface hints. | `apps/api/nope_api/attack_surface.py`, `apps/web/components/attack-map.tsx` | Interprocedural AST graph, call/data-flow edges, interactive zoom/filter UI. | Smoke scan and UI build. | None. |
| Scanner adapters | Complete | Plugin classes execute bundled CLIs, capture redacted raw output, record command/exit code, expose capabilities, normalize supported JSON outputs, and explicitly mark OWASP ZAP baseline skipped/not applicable for repository scans. | `apps/api/nope_api/scanners.py`, `apps/api/nope_api/models.py`, `apps/api/nope_api/main.py` | Broader rule-pack tuning belongs to scanner-quality iteration, not Phase 2 plumbing. | Backend scanner parser tests, `/health`, `/api/scanners/capabilities`, live fixture scan `scan_phase2_verify_20260715_zap_contract`. | None for bundled local repository scanner matrix. |
| Real scanner execution | Complete | API image bundles and runs Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, and Bandit; live fixture scan produced normalized findings for every executable repository scanner and persisted raw artifacts. OWASP ZAP baseline is represented as not applicable to repository scans because it requires a running HTTP target. | `apps/api/requirements.txt`, `apps/api/nope_api/scanners.py`, `docker/api.Dockerfile`, `security-packs/semgrep/nope.yml` | Real ZAP execution belongs to Dynamic testing/Phase 10 sandbox with a safe internal target. | Backend tests, Docker build, `/health`, scanner version checks, fixture scan `scan_phase2_verify_20260715_zap_contract`. | None for repository scanners; ZAP dynamic execution requires the later sandbox target. |
| Result parsing | Complete | Parsers normalize Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, and Bandit JSON outputs into shared findings. | `apps/api/nope_api/scanners.py`, `apps/api/tests/test_scanners.py` | SARIF import and additional edge-case fixtures can be added later. | `python -m pytest apps/api/tests`; live scan parsed 28 external scanner findings. | None. |
| Finding normalization | Partially complete | Custom rule and external scanner findings share the Pydantic model with normalized severity, confidence, evidence, remediation, file, line, source, and stable fingerprint. | `apps/api/nope_api/models.py`, `apps/api/nope_api/rules_engine.py`, `apps/api/nope_api/scanners.py` | Normalize CWE/CVSS/package metadata more deeply. | Rule and scanner parser tests. | None. |
| Deduplication | Partially complete | Custom-rule dedupe merges matching fingerprints in memory. | `apps/api/nope_api/rules_engine.py` | Cross-scanner correlation, recurrence, persistent fingerprints/history. | `python -m pytest`. | None. |
| Suppression/false-positive workflow | Not implemented | Finding status field exists, but no suppression model/API/UI. | `apps/api/nope_api/models.py`, `apps/web/app/app/projects/local/findings/page.tsx` | Persist suppression reason/user/expiry/scope and filters. | Code audit. | None. |
| Focused RAG | Partially complete | Lexical context builder selects finding evidence snippets for AI calls. | `apps/api/nope_api/ai.py` | Chunk repository evidence, metadata limits, prompt-injection controls, optional vector index. | Code audit; AI disabled path verified. | None. |
| Qwen runtime | Partially complete | `nope-ai` Compose service/profile exists; model file now confirmed at `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`. | `docker-compose.yml`, `docker-compose.ai-cpu.yml`, `docker-compose.ai-gpu.yml`, `LOCAL_AI.md` | Update env names/path, mount actual model, run CPU/GPU container, measure VRAM. | Model file check and `nvidia-smi`. | Local model exists; Docker AI profile not verified. |
| Qwen inference | Not implemented | Backend has `/completion` call path, but no live llama.cpp inference has been verified. | `apps/api/nope_api/ai.py`, `apps/api/nope_api/main.py` | Start llama.cpp, call health/completion, connect scan review. | Current health shows provider `none`. | Requires AI profile startup; model file available. |
| Reports JSON/Markdown/SARIF | Complete | Report endpoint renders JSON, Markdown and SARIF-like exports from real scan data; generated report bodies, hashes, media types, and byte sizes persist per scan/format. | `apps/api/nope_api/reports.py`, `apps/api/nope_api/main.py`, `apps/api/nope_api/storage.py`, `apps/api/migrations/0002_report_bodies.sql` | Richer methodology fields are later reporting polish. | Backend tests, build, API route audit, table-count smoke. | None. |
| PDF reports | Not implemented | No PDF generator or route exists. | `apps/api/nope_api/reports.py` | Add PDF generation, storage, authorization, pagination. | Code audit. | None. |
| Findings filters | Not implemented | Findings page displays table/detail but no real filters/search. | `apps/web/app/app/projects/local/findings/page.tsx`, `apps/web/components/finding-table.tsx` | Severity/confidence/scanner/status/CWE/stack/file filters and query APIs. | UI code audit. | None. |
| Finding evidence views | Partially complete | Table exposes evidence source count and detail panel shows remediation. | `apps/web/components/finding-table.tsx`, `apps/web/app/app/projects/local/findings/page.tsx` | Full evidence tabs, code snippets, exact line citations, raw scanner refs. | UI build. | None. |
| Code-flow views | Partially complete | Attack map canvas shows lightweight graph nodes. | `apps/web/components/attack-map.tsx` | Vulnerable path highlighting, filters, finding linkage, code-flow tabs. | UI build. | None. |
| Scan history | Partially complete | Scans page lists persisted user-scoped scans from Postgres. | `apps/web/app/app/projects/local/scans/page.tsx`, `apps/api/nope_api/storage.py` | Filtering, commit metadata enrichment, and scan attempts belong to later queue/history phases. | UI smoke and persistence tests. | None. |
| Baseline comparison | Not implemented | No baseline model/API/UI exists. | None | Add `SecurityBaseline`, scan comparison, finding recurrence/fixed/new/reintroduced. | Code audit. | None. |
| Security drift detection | Not implemented | No drift event model/API/UI exists. | None | Add drift events, coverage drift, trend visualization. | Code audit. | None. |
| Sandbox runner | Not implemented | Only security model/docs mention sandbox; no runner exists. | `SECURITY_MODEL.md`, `docker-compose.yml` | Add isolated container lifecycle, limits, logs, cleanup, safe commands. | Code audit. | Docker available. |
| Dynamic testing | Partially complete | URL scanner does safe non-destructive checks; no browser/ZAP dynamic scan. | `apps/api/nope_api/url_scanner.py` | ZAP baseline, sandboxed target, authenticated flow, dynamic evidence. | API smoke and code audit. | ZAP image not integrated. |
| Settings persistence | Partially complete | Phase 1 repository methods persist application settings, model configurations, and scanner configurations; UI/API still read runtime environment settings. | `apps/api/nope_api/storage.py`, `apps/api/nope_api/config.py`, `apps/api/nope_api/main.py`, `apps/web/app/app/projects/local/settings/page.tsx` | Phase 11 must add full settings API/UI validation, secret encryption, rotation, and project settings workflows. | Phase 1 contract entity tests; UI build and code audit. | None. |
| Scanner health/capability reporting | Complete | `/health` reports command availability and `/api/scanners/capabilities` returns installed status, version, coverage categories, and supported markers. | `apps/api/nope_api/scanners.py`, `apps/api/nope_api/main.py` | Enabled/disabled project policy can be added with settings persistence. | `GET /health`; authenticated `GET /api/scanners/capabilities`. | None. |
| GitHub contracts | Partially complete | Phase 1 schema contains connection, installation, and repository reference tables with blocked credential status; routes/adapters/UI remain Phase 11. | `apps/api/migrations/0001_initial.sql`, `README.md`, `apps/web/app/page.tsx`, `apps/web/app/app/projects/local/assets/page.tsx` | Add settings UI, callback route structure, adapter interfaces, credential state endpoints. | Code/docs audit. | None for local contracts. |
| GitHub private access | Blocked by external dependency | No GitHub App/OAuth credentials exist. | None | Configure GitHub App ID/client/private key/callback and implement token flow. | Credential audit. | Requires GitHub credentials. |
| MinIO artifact storage | Complete | Scanner raw stdout/stderr payloads are stored as JSON objects in MinIO and linked through `uploaded_artifacts`, `job_artifacts`, and `scanner_runs.raw_artifact_id`. | `apps/api/nope_api/artifacts.py`, `apps/api/nope_api/storage.py`, `docker-compose.yml` | Authorized artifact download route can be added when the UI needs direct raw-output viewing. | DB join and MinIO object listing for `scan_e1b6a69758a848bd`. | None. |
| Audit logs | Partially complete | Phase 1 schema and repository method can persist audit rows; application event coverage is not wired broadly yet. | `apps/api/nope_api/storage.py`, `apps/api/migrations/0001_initial.sql` | Wire auth, project, scan, settings, report events through audit logging. | Phase 1 contract entity tests. | None. |
| Benchmarks | Partially complete | One vulnerable Next fixture exists for tests. | `apps/api/tests/fixtures/vulnerable-next` | Add broader vulnerable fixtures and benchmark runner/expected results. | `python -m pytest`. | None. |
| Tests | Partially complete | 29 backend tests pass, including persistence, auth, scanner parsing/artifacts, queue execution, cancellation, retry/backoff, and scan events; no frontend/unit/E2E suite. | `apps/api/tests/test_pipeline.py`, `apps/api/tests/test_security.py`, `apps/api/tests/test_persistence.py`, `apps/api/tests/test_api_auth.py`, `apps/api/tests/test_scanners.py`, `apps/api/tests/test_queue.py` | RAG/Qwen/PDF/sandbox/settings/E2E/security expansion remains. | `python -m pytest apps/api/tests`, Docker Phase 3 queue proof. | Optional model tests need runtime. |
| Documentation | Partially complete | Core docs exist and Phase 0 now adds `docs/PHASE_RECONCILIATION.md`; later final docs remain absent until Phase 16. | `README.md`, `docs/ARCHITECTURE.md`, `docs/FEATURE_STATUS.md`, `docs/IMPLEMENTATION_WORKLOG.md`, `docs/PHASE_RECONCILIATION.md`, `docs/DATABASE.md`, `docs/API_REFERENCE.md` | Add/complete `PIPELINE.md`, `SANDBOX.md`, `BENCHMARKS.md`, `TROUBLESHOOTING.md`, and keep docs current through later phases. | Docs audit. | None. |
| Docker core stack | Complete | Web/API/worker/Postgres/Redis/MinIO start; primary container is named `NOPE`; health checks pass. | `docker-compose.yml`, `docker/api.Dockerfile`, `docker/web.Dockerfile` | Production gateway/resource limits/scanner jobs. | `docker compose up --build -d`, `docker compose ps`. | None. |
| Docker AI profile | Partially complete | AI service/profile exists but model path and inference are not verified. | `docker-compose.yml`, `docker-compose.ai-cpu.yml`, `docker-compose.ai-gpu.yml` | Mount `D:/Desktop/Model`, start llama.cpp, test health/completion, document VRAM. | Model file and GPU baseline collected. | Requires Docker AI image pull/runtime. |
| Resource controls | Partially complete | Archive/file/time/AI limits are configured; scanner subprocess timeout, whole-scan worker timeout, retry cap, and bounded backoff exist. | `apps/api/nope_api/config.py`, `apps/api/nope_api/ingestion.py`, `apps/api/nope_api/scanners.py`, `apps/api/nope_api/queue.py` | Concurrency limits, artifact quotas, per-project settings. | Tests and Docker queue proof. | None. |
| Observability | Partially complete | Scan IDs, stages, scanner statuses, queue status, scan events, worker heartbeat, and redacted worker failure messages exist. | `apps/api/nope_api/models.py`, `apps/api/nope_api/scan_engine.py`, `apps/api/nope_api/queue.py` | Structured logs, request IDs, metrics export. | `/api/scans/{id}/events`, `/api/queue/status`, Docker logs. | None. |
| Accessibility/responsive UI | Partially complete | Keyboard sidebar, responsive CSS and reduced motion exist. | `apps/web/app/globals.css`, `apps/web/components/line-sidebar.tsx` | Formal axe/Playwright audit, dialogs/forms/table improvements. | Web build and code audit. | None. |

## Phase 1 Completed

Phase 1 objective: replace the in-memory project/scan/finding/report state with migration-backed PostgreSQL persistence, authenticated ownership scoping, and durable generated report storage.

Phase 1 acceptance targets:

- Migrations create durable tables for users/sessions, projects, targets, repository sources/snapshots, scans, stages, scanner runs, findings, evidence, sources, history, coverage, reports, model/scanner/settings, baselines, drift events, artifacts, audit logs, and GitHub contract entities.
- The normal scan path persists project, scan, finding, coverage, stage, scanner-run, and generated report payloads to Postgres.
- API restart does not lose scans.
- Local auth remains functional.
- Existing tests continue to pass, with new persistence tests added.

## Phase 1 Result

Phase 1 status: Complete for local persistence scope.

Verification evidence:

- Added SQL migration runner, migration status reporting, initial schema migration, and report-body migration.
- Added durable tables for local auth, projects, targets, repository sources/snapshots, scans, stages, scanner runs, findings, evidence, sources, history, coverage, reports, settings, baselines, drift events, artifacts, audit logs, and GitHub contract entities.
- Replaced `InMemoryStore` with `PostgresStore`.
- Added persistence/auth tests; backend test count is now 16.
- Verified a ZIP scan through the web route persisted and remained readable after `nope-api` restart.
- Verified normalized table rows exist for scans, stages, scanner runs, findings, coverage, reports, and schema migrations.
- Protected API endpoints now require a local bearer token by default and are user-scoped.
- Generated JSON, Markdown, and SARIF report bodies persist in Postgres with body hashes and byte counts.

Phase 1 is closed. Redis-backed queued scan execution remains a later worker phase; scanner execution and artifact handling are now closed in Phase 2.

## Phase 2 Completed

Phase 2 objective: make external scanner execution real enough to produce normalized findings and durable scanner-run evidence without faking unavailable tools.

Phase 2 result:

- Added normalized JSON parsers for Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, and Bandit.
- Added command, exit-code, redacted stdout, and redacted stderr fields to scanner runs.
- Added bounded scanner output storage through `NOPE_MAX_SCANNER_OUTPUT_BYTES`.
- Bundled Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, and Bandit in the API image.
- Added local Semgrep rules under `security-packs/semgrep/nope.yml`.
- Added scanner parser, capability, and scanner execution artifact tests.
- Added MinIO raw scanner artifact storage with `uploaded_artifacts`, `job_artifacts`, and `scanner_runs.raw_artifact_id` links.
- Added authenticated `/api/scanners/capabilities` with scanner versions, coverage categories, and supported markers.
- Added `docs/SCANNERS.md`.
- Verified Docker API image reports all bundled scanners installed.
- Verified scanner versions: Semgrep `1.169.0`, Bandit `1.9.4`, Gitleaks `8.28.0`, OSV-Scanner `2.2.3`, Trivy `0.72.0`, Checkov `3.3.8`, Hadolint `2.14.0`.
- Verified authenticated ZIP scan `scan_e1b6a69758a848bd` completed with 29 findings: NOPE rules 1, Semgrep 1, Gitleaks 1, OSV-Scanner 5, Trivy 10, Checkov 6, Hadolint 2, Bandit 3.
- Verified MinIO object storage and DB artifact joins for all seven external scanner raw-output artifacts in `scan_phase2_verify_20260715_zap_contract`.

Phase 2 status: Complete for the bundled repository scanner execution and evidence pipeline. OWASP ZAP baseline is explicitly present in the scanner contract and skipped/not applicable for repository scans.

Out of scope for Phase 2 and still tracked separately: Redis worker queue, real ZAP/browser dynamic testing against an internal target, Qwen inference, suppression workflow, and PDF reports.

## Phase 3 Completed

Phase 3 objective: move scan execution behind a real Redis queue and worker while preserving durable progress, cancellation, retry, and restart behavior.

Phase 3 result:

- API scan start endpoints now validate and persist queued scans, then return before scan execution.
- Repository/full scans extract ZIP uploads into the shared `/app/.nope-workspaces` Docker volume for worker access.
- Redis jobs include job IDs, active-scan idempotency, attempts, maximum attempts, and run-after timestamps.
- Worker consumes Redis jobs, persists stage checkpoints, writes final findings/scanner runs, emits heartbeat, and reconnects after Redis loop failures.
- Cancellation is requested through Redis flags and checked before work plus between scan-engine checkpoints.
- Retry endpoint clears cancellation flags and requeues failed/partial/cancelled/completed scans when the workspace is available.
- Queue status, worker health, and scan events endpoints expose reload-safe progress.
- Docker image/volume permissions now allow the non-root API and worker users to share repository workspaces.

Verification evidence:

- `python -m pytest apps/api/tests`: 29 passed.
- Docker images refreshed: API `903026c0b97a`, worker `bda4f232c33b`.
- Queued two scans through the real API with the worker stopped; both returned `queued` immediately.
- Restarted API before worker execution; worker later completed `scan_4ebe1b771ac7413b` with 29 findings.
- Cancelled queued scan `scan_c8fbd2708e4044e6`; worker persisted `cancelled` without running scanners.
- Interrupted worker during `scan_6ede29d9d13d4778`, requeued the processing payload, and completed the scan after worker restart with 29 findings.
- Retried failed scan `scan_phase3_retry_failed` through the API retry endpoint; worker completed it with 29 findings.
- Stopped Redis; `/api/queue/status` returned `redis:error`, and the rebuilt worker stayed alive and restarted its queue loop after Redis returned.

Phase 3 status: Complete for Redis-backed local queue and worker orchestration.
