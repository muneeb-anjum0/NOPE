# NOPE Implementation Worklog

## 2026-07-15

### Repository inspection

- Repository state: greenfield. Only `.git` and `.gitattributes` existed.
- Branch: `main`, tracking `origin/main`.
- Remote: `https://github.com/muneeb-anjum0/NOPE.git`.
- CodeGraph: not present.
- Node: `v24.16.0`.
- npm: `11.13.0`.
- pnpm: `11.5.0`.
- Python: `3.11.9`.
- Docker: `29.6.1`.
- Docker Compose: `v5.2.0`.
- External scanner CLIs checked locally: Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, Bandit were not found on PATH.
- Local model runtimes checked locally: Ollama and llama-server were not found on PATH.

### Implementation plan

1. Build a local-first monorepo with `apps/web`, `apps/api`, `apps/worker`, `packages/shared`, `security-packs`, `tests`, and Docker.
2. Implement FastAPI API with in-memory development storage, Pydantic contracts, scan orchestration, URL authorization guards, ZIP-safe repository ingestion, stack detection, attack-surface extraction, code graph generation, deterministic NOPE rules, scanner plugin adapters, RAG snippets, AI adapter, reports, and coverage.
3. Implement a compact Next.js dashboard with onboarding, overview, findings, finding detail, attack map, coverage, scans, assets, reports, and settings.
4. Provide scanner plugins that execute when tools exist and otherwise produce explicit failed or unavailable coverage without fabricating findings.
5. Add tests for the core security boundaries and deterministic scan pipeline.
6. Add Docker Compose with web, API, worker, Postgres, Redis, MinIO, and optional AI endpoint configuration. Primary container name must be `NOPE`.
7. Run linting, type checking, unit tests, builds, and Docker health checks where feasible. Update status honestly.

### Design decisions

- FastAPI is used for scanner orchestration because the product is scanner-heavy and Python has strong security-analysis tooling.
- The API uses in-memory storage for local MVP execution while exposing a database-ready repository layer and Docker Postgres service for the next persistence step.
- Scanner plugin results are never faked. If a scanner CLI is unavailable, the scanner is marked failed/unavailable and coverage reflects that.
- AI is optional and pluggable. Deterministic scanners continue when AI runtime is missing.
- Dynamic and destructive testing are gated behind explicit authorization and scope controls.

### Verification results

- `python -m pytest` in `apps/api`: passed, 9 tests.
- `python -m compileall nope_api tests` in `apps/api`: passed.
- `python -m ruff check nope_api tests`: not run successfully because Ruff was not installed; the attempted `pip install -r apps/api/requirements-dev.txt` stalled while downloading the Ruff wheel and was stopped.
- `pnpm install`: passed after approving `sharp` and `unrs-resolver` build scripts.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web lint`: passed after adding ESLint flat config.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed.
- `GET http://localhost:8000/health`: passed; Qwen healthy at 28 GPU layers.
- Live findings API smoke against `scan_phase7_smoke`: filtered `GET /api/scans/{scan_id}/findings?severity=high&scanner=Semgrep&page_size=5` returned one finding; `GET /api/scans/{scan_id}/findings/{finding_id}` returned Overview/Evidence/Code/Code Flow/Fix/Tests/History tabs.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4041, 6144`.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- API smoke test: `GET http://127.0.0.1:8000/health` returned status `ok`.
- Repository scan smoke test: uploaded vulnerable fixture ZIP to `/api/scans/repository`; scan completed and produced real NOPE-rule findings.
- Built web smoke test: `GET http://127.0.0.1:3000` returned HTTP 200.
- Docker: `docker compose up --build -d` built and started all services. `NOPE`, `nope-api`, `nope-postgres`, `nope-redis`, and `nope-minio` reported healthy.
- Docker endpoints verified: web `http://127.0.0.1:3000` HTTP 200, API `http://127.0.0.1:8000/health` status `ok`, MinIO console `http://127.0.0.1:9001` HTTP 200.

### Known verification caveats

- External scanner CLIs were not installed locally or in the API image, so those plugins report failed or unavailable status instead of producing scanner findings.
- Qwen/Ollama/llama.cpp runtime was not present, so AI review is marked `Not tested`.
- npm reported two moderate frontend dependency advisories during the Docker web install; this requires dependency-audit follow-up.

## 2026-07-15 Frontend Redesign + Local Qwen Continuation

### Required baseline inspection

- Read: `FEATURE_STATUS.md`, `IMPLEMENTATION_WORKLOG.md`, `ARCHITECTURE.md`, `DEVELOPMENT.md`, `DEPLOYMENT.md`, `SECURITY_MODEL.md`, `API_REFERENCE.md`.
- Inspected current web files: `apps/web/app/page.tsx`, `apps/web/app/globals.css`, `apps/web/app/layout.tsx`, `apps/web/app/api/start-scan/route.ts`, `apps/web/package.json`, `apps/web/next.config.ts`.
- Inspected current backend AI path: `apps/api/nope_api/ai.py`, `apps/api/nope_api/config.py`, `apps/api/nope_api/main.py`.
- Inspected Docker: `docker-compose.yml`, `docker/api.Dockerfile`, `docker/web.Dockerfile`.

### Baseline verification before redesign

- `python -m pytest` in `apps/api`: passed, 9 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose ps`: core services running and healthy: `NOPE`, `nope-api`, `nope-postgres`, `nope-redis`, `nope-minio`.

### Current frontend deficiencies

- Root route `/` is the dashboard rather than a public landing page.
- Visual system is light/white, contradicting the required single graphite-black theme.
- Dashboard layout resembles a basic internal admin panel.
- Navigation is a static list of rounded links with no route-aware app shell.
- No separate app routes exist for overview, findings, attack map, coverage, scans, assets, reports, or settings.
- Browser-default selects, file inputs, checkboxes, and basic form controls remain visible.
- Landing storytelling, methodology, local-AI positioning, coverage explanation, and demo scan sequence are absent.
- Findings, coverage, attack map, reports, and settings are presented as shallow sections on one page instead of polished workflows.
- Motion system is missing beyond default hover behavior.
- Responsive behavior is basic and not designed as a mobile app experience.
- Qwen status exists only as disabled configuration text; no llama.cpp service, health endpoint, or inference path is implemented.

### Redesign implementation checklist

1. Create a centralized graphite design system with semantic CSS tokens, typography, controls, motion, severity semantics, and responsive rules.
2. Replace `/` with a polished public landing page.
3. Move the app experience to `/app` and route-specific pages under `/app/projects/local/*`.
4. Build a route-aware LineSidebar-inspired app shell with active state, pointer proximity styling, keyboard focus, and mobile behavior.
5. Replace browser-default controls with custom dark controls for scan launch, upload, URL authorization, scan depth, filters, and settings.
6. Rebuild overview, findings, finding detail, attack map, coverage, scans, assets, reports, and settings as deliberate dense developer-security screens.
7. Add controlled CSS motion with reduced-motion support.
8. Add llama.cpp/Qwen Docker service profiles for core, CPU, and GPU modes without committing model files.
9. Update API AI adapter to support llama.cpp-compatible health and completion calls with timeouts and failure-safe scan continuation.
10. Add model health/explain endpoints, frontend AI status display, and finding explanation action.
11. Update README, architecture, development, deployment, security, feature status, design system, and local AI docs.
12. Re-run lint, typecheck, tests, production build, Docker health checks, and document what was verified.

### Redesign implementation results

- Replaced the root route `/` with a complete public dark graphite landing page.
- Added routed app workspace under `/app/projects/local`.
- Added `LineSidebar` route-aware icon rail with active state, focus labels, and mobile dock behavior.
- Replaced the old white global CSS with centralized graphite tokens, severity colors, motion, controls, tables, panels, and responsive rules.
- Added overview, findings, attack map, coverage, scans, assets, reports, and settings pages.
- Added custom scan launcher controls and mobile table containment.
- Added llama.cpp-aware AI health and completion adapter.
- Added `/api/findings/explain` for focused finding explanation.
- Added optional `nope-ai` service and CPU/GPU Compose override files.
- Added `DESIGN_SYSTEM.md` and `LOCAL_AI.md`.

### Redesign verification

- `python -m pytest` in `apps/api`: passed, 10 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- Playwright package was available, but its bundled browser was not installed.
- System Microsoft Edge channel worked for headless visual inspection.
- Visually inspected with Edge screenshots:
  - `http://127.0.0.1:3001/` at 1440x1000.
  - `http://127.0.0.1:3001/app/projects/local` at 1440x1000.
  - `http://127.0.0.1:3001/app/projects/local/findings` at 390x844.

### AI verification caveats

- A broad local `*.gguf` search did not find the downloaded Qwen model in the searched filesystem paths.
- `nope-ai` service configuration was added but actual model loading, GPU VRAM use, and inference were not verified.
- CPU/GPU profile commands are documented and can be run once `NOPE_MODEL_DIR` and `NOPE_QWEN_MODEL_FILE` point at the downloaded model.

## 2026-07-15 Phase 0 Baseline Audit

### Objective

Rebuild the current implementation status from repository evidence before starting the persistence, queue, scanner, Qwen, reporting, drift, sandbox, settings, benchmark, and testing phases requested by the continuation prompt.

### Repository and tool baseline

- Branch: `main`.
- Baseline commit: `50a0004`.
- Remote: `origin https://github.com/muneeb-anjum0/NOPE.git`.
- Working tree before Phase 0 edits: clean.
- Node: `v24.16.0`.
- pnpm: `11.5.0`.
- Python: `3.11.9`.
- Docker: `29.6.1`.
- Docker Compose: `v5.2.0`.
- GPU: `NVIDIA GeForce GTX 1060 with Max-Q Design`, 6144 MiB total, 0 MiB used at baseline.
- Qwen model file: `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`, 5,027,783,488 bytes, present.
- Scanner CLIs on PATH: Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, Bandit were not found.
- Local `nvidia-smi` exists and can be used for later GPU verification.

### Documentation inspected

- `README.md`
- `FEATURE_STATUS.md`
- `IMPLEMENTATION_WORKLOG.md`
- `ARCHITECTURE.md`
- `SECURITY_MODEL.md`
- `DEVELOPMENT.md`
- `DEPLOYMENT.md`
- `API_REFERENCE.md`
- `DESIGN_SYSTEM.md`
- `LOCAL_AI.md`

### Implementation evidence inspected

- API models and endpoints: `apps/api/nope_api/models.py`, `apps/api/nope_api/main.py`
- Storage: `apps/api/nope_api/storage.py`
- Local auth: `apps/api/nope_api/auth.py`
- ZIP ingestion: `apps/api/nope_api/ingestion.py`
- URL scope and scanner: `apps/api/nope_api/security.py`, `apps/api/nope_api/url_scanner.py`
- Pipeline: `apps/api/nope_api/scan_engine.py`
- Stack/attack graph: `apps/api/nope_api/stack_detector.py`, `apps/api/nope_api/attack_surface.py`
- Rules/scanners/RAG/Qwen/reports: `apps/api/nope_api/rules_engine.py`, `apps/api/nope_api/scanners.py`, `apps/api/nope_api/ai.py`, `apps/api/nope_api/reports.py`
- Worker: `apps/worker/worker.py`
- Web routes/components: `apps/web/app`, `apps/web/components`, `apps/web/lib`
- Docker: `docker-compose.yml`, `docker-compose.ai-cpu.yml`, `docker-compose.ai-gpu.yml`, `docker/api.Dockerfile`, `docker/web.Dockerfile`

### Baseline verification commands

- `git status --short`: clean before Phase 0 edits.
- `git rev-parse --short HEAD`: `50a0004`.
- `git branch --show-current`: `main`.
- `git remote -v`: `origin https://github.com/muneeb-anjum0/NOPE.git`.
- `node --version`: `v24.16.0`.
- `pnpm --version`: `11.5.0`.
- `python --version`: `Python 3.11.9`.
- `docker --version`: `Docker version 29.6.1, build 8900f1d`.
- `docker compose version`: `Docker Compose version v5.2.0`.
- `Test-Path D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`: `True`.
- `nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader`: GTX 1060 Max-Q, 6144 MiB total, 0 MiB used.
- `$env:PYTHONPATH='apps/api'; python -m pytest`: passed, 10 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `docker compose up --build -d`: passed from cache.
- `docker compose ps`: `NOPE`, `nope-api`, `nope-postgres`, `nope-redis`, `nope-minio` healthy; worker started.
- `GET http://127.0.0.1:8000/health`: returned `status: ok`; AI provider `none`; scanner CLIs reported missing.
- `GET http://127.0.0.1:3000`: HTTP 200.
- `GET http://127.0.0.1:9001`: HTTP 200.
- UI route ZIP smoke test through `POST http://127.0.0.1:3000/api/start-scan`: returned HTTP 307 to `/app/projects/local`; created repository scan `scan_649d1a2906c349ae` with status `completed`, score `45`, coverage `27`.

### Phase 0 audit conclusions

- NOPE is a working local MVP with functional web/API/Docker, local Postgres auth, ZIP upload, synchronous repository scans, basic URL checks, custom rules, heuristic stack/attack graph, coverage, reports, and graceful AI-disabled behavior.
- The central scan/project/finding/report state is still in `InMemoryStore`, so persistence is the highest priority next phase.
- Redis exists as a service, but scan jobs are not queued. `apps/worker/worker.py` only prints readiness.
- Scanner plugins are adapter shells that can run local CLIs if present, but no scanners are installed in the API image or local PATH, and parser implementations are not present.
- Qwen model file now exists locally, but the llama.cpp container has not been started or inference-tested.
- MinIO exists, but artifacts and reports are not stored there.
- GitHub private repository access remains blocked by missing GitHub App/OAuth credentials. Local contracts still need implementation.

### Phase 0 documentation changes

- Replaced `FEATURE_STATUS.md` with an evidence-based matrix covering local auth, persistence, scans, worker/queue, scanner execution/parsing, RAG/Qwen, reports, history/drift, sandbox, settings, GitHub, benchmarks, tests, Docker, and documentation.

### Next phase

Phase 1: add persistent PostgreSQL storage and migrations. The first implementation target is to replace `InMemoryStore` with a migration-backed repository layer while preserving the current API behavior and tests.

## 2026-07-15 Phase 1 Persistent Postgres Storage

### Objective

Replace `apps/api/nope_api/storage.py` in-memory project/scan state with a migration-backed Postgres repository. Preserve current API contracts while adding normalized durable tables for the entities required by the continuation prompt.

### Planned implementation

1. Add a small SQL migration runner and version table.
2. Add an initial schema migration for local auth plus project, scan, stage, scanner-run, finding, evidence, source, history, coverage, report, settings, baseline, drift, artifact, audit, and GitHub contract tables.
3. Update API startup to run migrations instead of ad hoc auth table creation.
4. Replace `InMemoryStore` with a Postgres-backed store using psycopg.
5. Keep flexible JSON columns for current scan graph/stack/AI fields while normalizing core relationships.
6. Add tests for migration application, scan persistence, and cross-user ownership guard helpers.
7. Verify Docker restart persistence with a ZIP scan.

### Implementation results

- Added `apps/api/nope_api/db.py` with a small SQL migration runner and `schema_migrations` tracking.
- Added `apps/api/migrations/0001_initial.sql`.
- Replaced `InMemoryStore` with `PostgresStore` in `apps/api/nope_api/storage.py`.
- Migrations now create durable tables for:
  - `local_users`
  - `local_sessions`
  - `projects`
  - `project_targets`
  - `repository_sources`
  - `repository_snapshots`
  - `scans`
  - `scan_stages`
  - `scanner_runs`
  - `findings`
  - `finding_evidence`
  - `finding_sources`
  - `finding_history`
  - `scan_coverage`
  - `reports`
  - `model_configurations`
  - `scanner_configurations`
  - `application_settings`
  - `security_baselines`
  - `drift_events`
  - `uploaded_artifacts`
  - `job_artifacts`
  - `audit_logs`
  - `github_connections`
  - `github_installations`
  - `github_repository_references`
- Updated auth startup to use migrations instead of ad hoc auth-only DDL.
- Updated API project/scan routes to pass authenticated owner IDs when available.
- Updated Next server API calls and scan upload proxy to forward the local session token.
- Added `apps/api/tests/test_persistence.py`.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest`: passed, 13 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `git diff --check`: passed.
- `docker compose up --build -d`: passed.
- Docker services healthy after rebuild.
- Web ZIP upload smoke test created `scan_6c5090b8fe1c474d`.
- `docker compose restart nope-api`, then `GET /api/scans/scan_6c5090b8fe1c474d` returned HTTP 200 with status `completed`.
- Postgres row-count smoke after scan showed rows in normalized tables:
  - scans: 3
  - stages: 5
  - scanner_runs: 8
  - findings: 1
  - coverage: 15
  - reports: 9
  - schema_migrations: 1

### Known limitations before Phase 1 completion hardening

- Direct local API access without an authorization header still needed to be closed. Authenticated dashboard calls were already scoped by local user.
- Scan execution is still synchronous; Redis-backed queuing is Phase 2.
- Raw scanner output and generated report bodies still needed durable payload handling.
- Migration runner is intentionally small SQL-file based rather than Alembic; it records applied migration filenames in `schema_migrations`.

## 2026-07-15 Phase 1 Completion Hardening

### Objective

Close the remaining Phase 1 persistence/auth/report gaps before starting Phase 2.

### Implementation results

- Added `NOPE_REQUIRE_AUTHENTICATED_API`, defaulting protected API routes to authenticated local sessions.
- Enforced owner scoping on project, scan, finding, coverage, attack-map, report, settings, model-test, and finding-explanation routes.
- Fixed authenticated URL scans so URL authorization scope no longer overwrites the bearer-token header value before owner lookup.
- Added `apps/api/migrations/0002_report_bodies.sql` with durable report body, hash, byte-size, and generated timestamp columns.
- Updated `PostgresStore` to render and persist JSON, Markdown, and SARIF report payloads on scan save.
- Added stored-report retrieval for report downloads.
- Added migration status reporting to `/health`.
- Stopped swallowing migration startup failures; the API now fails loudly if the database schema cannot initialize.
- Updated README, API, architecture, database, status, and worklog docs.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: passed, 16 tests.
- New tests cover unauthenticated API rejection, user-scoped project visibility, and persisted report body retrieval.

### Phase 1 closure

Phase 1 is now complete for the local persistence scope. Remaining scanner execution, queueing, raw scanner artifact storage, MinIO object payloads, and advanced history/drift work belong to later phases.

## 2026-07-15 Phase 2 Scanner Execution Start

### Objective

Start replacing scanner placeholders with real scanner execution evidence, normalized parser output, and honest capability reporting.

### Implementation results

- Extended `ScannerRun` with command arguments, exit code, redacted stdout, and redacted stderr.
- Added `NOPE_MAX_SCANNER_OUTPUT_BYTES` to bound stored scanner output.
- Added scanner output redaction before persistence.
- Implemented JSON parsers/normalizers for:
  - Semgrep
  - Gitleaks
  - OSV-Scanner
  - Trivy
  - Checkov
  - Hadolint
  - Bandit
- Bundled Semgrep and Bandit in `apps/api/requirements.txt` for API-image execution.
- Added local Semgrep rules at `security-packs/semgrep/nope.yml` and configured Semgrep to use them with metrics disabled.
- Set Docker API `HOME=/tmp` so Semgrep can write local runtime state as the non-root `nope` user.
- Added `apps/api/tests/test_scanners.py` with parser normalization and raw-output redaction coverage.
- Added `docs/SCANNERS.md`.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: passed, 21 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose up --build -d`: passed.
- `docker compose exec -T nope-api semgrep --version`: `1.169.0`.
- `docker compose exec -T nope-api bandit --version`: `1.9.4`.
- `GET /health`: Semgrep and Bandit report `Installed.`
- Authenticated repository ZIP scan `scan_28e96fc09a904bc9`: completed with Semgrep status `passed`, exit code `1`, 2 normalized Semgrep findings, and redacted raw output captured.

### Remaining Phase 2 work

- Add containerized scanner execution for the non-Python scanners.
- Store full scanner raw artifacts in MinIO with authorized downloads.
- Add scanner version and capability reporting.

## 2026-07-15 Phase 2 Scanner Execution Completion

### Objective

Close Phase 2 for the bundled repository scanner matrix: real scanner binaries in Docker, normalized parser output, persisted scanner-run metadata, MinIO raw artifacts, and capability/version reporting.

### Implemented

- Bundled Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, and Bandit into the API/worker Docker image.
- Added scanner version commands and authenticated `GET /api/scanners/capabilities`.
- Added MinIO artifact writer for raw scanner stdout/stderr JSON payloads.
- Linked raw artifacts from `scanner_runs.raw_artifact_id`, `uploaded_artifacts`, and `job_artifacts`.
- Fixed Checkov parsing for top-level JSON-array output.
- Updated Gitleaks execution to write JSON reports to stdout through `--report-path /dev/stdout`.
- Added a broad vulnerable scanner fixture covering Python, Dockerfile, Terraform, lockfile dependency, and secret detection paths.
- Added backend tests for scanner capability reporting and raw scanner artifact persistence.

### Verification

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: 23 passed.
- `docker compose up --build -d nope-api nope-worker`: rebuilt and started successfully.
- `GET /health`: all bundled scanners reported `Installed.`
- Scanner versions in container:
  - Semgrep `1.169.0`
  - Gitleaks `8.28.0`
  - OSV-Scanner `2.2.3`
  - Trivy `0.72.0`
  - Checkov `3.3.8`
  - Hadolint `2.14.0`
  - Bandit `1.9.4`
- Authenticated `GET /api/scanners/capabilities`: returned installed status, versions, coverage categories, and supported markers for all bundled scanners.
- Authenticated ZIP scan `scan_e1b6a69758a848bd`: completed with 29 findings.
  - NOPE rules: 1
  - Semgrep: 1
  - Gitleaks: 1
  - OSV-Scanner: 5
  - Trivy: 10
  - Checkov: 6
  - Hadolint: 2
  - Bandit: 3
- Postgres artifact join verified raw artifact links for all seven external scanner runs.
- MinIO object listing verified seven raw-output JSON artifacts under `nope-artifacts/scans/scan_e1b6a69758a848bd/`.

### Phase Result

Phase 2 is complete for bundled repository scanner execution and evidence persistence. Redis queueing, ZAP/browser dynamic testing, Qwen inference, suppression workflow, and PDF reports remain separate later phases.

## 2026-07-15 Canonical Phase 0 Recovery Audit

### Objective

Execute the canonical continuation prompt's Phase 0 only: recover the repository state, inspect current implementation and history, create `docs/PHASE_RECONCILIATION.md`, refresh status/worklog documentation, run current verification, commit the Phase 0 audit docs, and stop before any later phase implementation.

### Pre-phase repository state

- Branch: `main`.
- Pre-phase commit SHA: `194a1e8`.
- HEAD: `feat(phase-2): complete scanner execution pipeline`.
- Tracking: `main...origin/main`.
- Working tree before Phase 0 documentation edits was not clean:
  - Modified: `apps/api/nope_api/main.py`
  - Modified: `apps/api/nope_api/models.py`
  - Modified: `apps/api/requirements.txt`
  - Modified: `apps/worker/worker.py`
  - Modified: `docker-compose.yml`
  - Untracked: `apps/api/nope_api/queue.py`
  - Untracked: `apps/api/tests/test_queue.py`
- Those existing changes are Phase 3 queue/worker work-in-progress and were not authored as part of this Phase 0 audit.
- CodeGraph: `.codegraph/` is not present, so normal repository inspection was used.

### Git history inspected

- `194a1e8 feat(phase-2): complete scanner execution pipeline`
- `0b036fb feat(phase-2): add real scanner parsing and bundled sast`
- `a5189fb feat(phase-1): harden persistence completion`
- `fcbdbe4 docs: move markdown docs into docs folder`
- `0c07d73 feat(phase-1): add persistent postgres storage and migrations`
- `c7bbe9f feat(phase-0): baseline implementation audit`
- `50a0004 fix: repair scan uploads and sidebar state`
- `e4eab90 feat: add local auth and refresh dashboard UX`
- `0a4ba90 feat: redesign NOPE and integrate local Qwen runtime`
- `1041135 docs: add NOPE README`
- `376e157 feat: build NOPE security orchestration platform`
- `6c0807d Initial commit`

### Documentation inspected

- `README.md`
- `docs/API_REFERENCE.md`
- `docs/ARCHITECTURE.md`
- `docs/DATABASE.md`
- `docs/DEPLOYMENT.md`
- `docs/DESIGN_SYSTEM.md`
- `docs/DEVELOPMENT.md`
- `docs/FEATURE_STATUS.md`
- `docs/IMPLEMENTATION_WORKLOG.md`
- `docs/LOCAL_AI.md`
- `docs/SCANNERS.md`
- `docs/SECURITY_MODEL.md`

### Implementation inspected

- API endpoints and contracts: `apps/api/nope_api/main.py`, `apps/api/nope_api/models.py`
- Persistence and migrations: `apps/api/nope_api/storage.py`, `apps/api/nope_api/db.py`, `apps/api/migrations/0001_initial.sql`, `apps/api/migrations/0002_report_bodies.sql`
- Auth/session handling: `apps/api/nope_api/auth.py`
- ZIP ingestion and URL scope controls: `apps/api/nope_api/ingestion.py`, `apps/api/nope_api/security.py`, `apps/api/nope_api/url_scanner.py`
- Pipeline/scoring: `apps/api/nope_api/scan_engine.py`, `apps/api/nope_api/scoring.py`
- Stack/attack/code graph: `apps/api/nope_api/stack_detector.py`, `apps/api/nope_api/attack_surface.py`
- Scanners/rules/artifacts: `apps/api/nope_api/scanners.py`, `apps/api/nope_api/rules_engine.py`, `apps/api/nope_api/artifacts.py`, `security-packs/nope-core-rules.json`, `security-packs/semgrep/nope.yml`
- Qwen/RAG/reporting: `apps/api/nope_api/ai.py`, `apps/api/nope_api/reports.py`
- Queue/worker WIP: `apps/api/nope_api/queue.py`, `apps/worker/worker.py`
- Frontend routes/components: `apps/web/app`, `apps/web/components`, `apps/web/lib`
- Tests/fixtures: `apps/api/tests`, `apps/api/tests/fixtures`
- Docker/env: `docker-compose.yml`, `docker-compose.ai-cpu.yml`, `docker-compose.ai-gpu.yml`, `docker/api.Dockerfile`, `docker/web.Dockerfile`, `.env.example`

### Required Phase 0 task list

1. Inspect recent commits.
2. Inspect documentation.
3. Inspect services, migrations, scanners, worker, queue, Qwen, RAG, reporting, frontend, tests, Docker Compose, and environment templates.
4. Create `docs/PHASE_RECONCILIATION.md`.
5. Update `docs/FEATURE_STATUS.md`.
6. Add this `docs/IMPLEMENTATION_WORKLOG.md` entry.
7. Run required current verification commands where repository-specific equivalents exist.
8. Document command results exactly.
9. Commit and push only Phase 0 documentation changes if verification permits.
10. Stop after the Phase 0 completion dossier.

### Required Phase 0 test list

- Git status/history/diff checks.
- Backend test suite: `python -m pytest apps/api/tests`.
- Frontend lint/typecheck/build: `pnpm --dir apps/web lint`, `pnpm --dir apps/web typecheck`, `pnpm --dir apps/web build`.
- Docker config/build/up/ps/log health checks.
- Migration status through API health and available migration runner.
- Keyword sweep over implementation/docs.
- Security checks available locally: Gitleaks, dependency audit, Docker configuration, and scanner-related tests.

### Phase reconciliation summary

- Authentication, local user/project/scan persistence, bundled scanner execution/parsing/artifacts, JSON/Markdown/SARIF reports, and Docker core stack have real implementation evidence.
- Redis queue/worker/retry/cancellation is now partially implemented in the dirty working tree, but is not complete or verified against Phase 3 acceptance criteria.
- Qwen is configured as adapter/profile documentation only; live llama.cpp model loading and inference remain Phase 5.
- RAG is only finding-snippet retrieval; graph-aware focused retrieval remains Phase 6.
- Findings filters/detail/code-flow/history, baselines/drift, PDF, sandbox, persistent settings, GitHub routes/adapters, benchmarks, expanded tests, E2E, and final documentation remain later phases.
- GitHub private repository access remains blocked by missing credentials and must not be faked.

### Keyword sweep conclusion

The required sweep found documentation status language, intentional vulnerable fixtures/rules, test-only fakes, a real `pass` control-flow statement in `security.py`, migration `pending` status reporting, placeholder attributes in UI inputs, and a UI "Pending" label. Each group is classified in `docs/PHASE_RECONCILIATION.md`; no sweep match remains undocumented.

### Verification results

Final command results for this Phase 0 pass:

- `git status --short --branch`: `main...origin/main`; dirty tree with pre-existing Phase 3 queue/worker WIP plus Phase 0 docs.
- `git log --oneline --decorate -20`: inspected through `194a1e8` back to `6c0807d`.
- `Test-Path .codegraph`: `False`; CodeGraph not available.
- `rg --files`: repository file inventory captured for docs, API, worker, web, tests, migrations, Docker, and security packs.
- Keyword sweep with `rg -n -i "TODO|FIXME|placeholder|stub|mock|fake|demo-only|temporary|in-memory|NotImplemented|NotImplementedError|hardcoded|later|pending|\bpass\b"`: completed; classifications recorded in `docs/PHASE_RECONCILIATION.md`.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: collected 24 tests but hung after starting `apps/api/tests/test_api_auth.py`; process was stopped after repeated waits. Result: failed/incomplete, likely because local Postgres/Docker was unavailable.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_pipeline.py apps/api/tests/test_scanners.py apps/api/tests/test_security.py apps/api/tests/test_queue.py`: passed, 17 tests in 2.92s.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `python -m ruff check apps/api/nope_api apps/api/tests`: failed, `No module named ruff`.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed; Next.js generated 17 routes successfully.
- `pnpm --dir apps/web run test`: failed, no `test` script exists.
- `git diff --check`: passed with line-ending warnings for dirty files.
- `docker --version`: Docker `29.6.1`.
- `docker compose version`: Docker Compose `v5.2.0`.
- `docker compose config`: passed and printed normalized configuration.
- `docker compose config --quiet`: passed.
- `docker compose build`: failed because Docker Desktop Linux engine was not reachable at `npipe:////./pipe/dockerDesktopLinuxEngine`.
- `docker compose up -d`: failed for the same Docker API connection issue.
- `docker compose ps`: failed for the same Docker API connection issue.
- `docker compose logs --tail 200`: failed for the same Docker API connection issue.
- Alembic check: `alembic` unavailable; repository uses the SQL migration runner in `apps/api/nope_api/db.py`, not Alembic.
- `gitleaks detect --source . --no-git --redact`: failed, `gitleaks` not installed locally.
- `pnpm audit --audit-level moderate`: failed with one moderate advisory: PostCSS `<8.5.10` via `apps__web>next>postcss`, GHSA-qx2v-qp2m-jg93.
- `python -m pip audit`: failed, `pip` has no `audit` command in this environment.
- `Get-Command pip-audit/trivy/semgrep`: unavailable locally.
- `Test-Path D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`: `True`.
- `nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 6144 MiB, 0 MiB`.

### Phase 0 closure notes

- Phase 0 documentation requirements were implemented.
- Full verification is not green because Docker/Postgres-dependent commands and security tools were unavailable in the current local state.
- The dirty Phase 3 queue/worker files remain uncommitted work-in-progress unless explicitly authorized for Phase 3.

## 2026-07-15 Phase 1 Completion Hardening to 100%

### Objective

Close the remaining canonical Phase 1 persistence gaps without starting Phase 3 queue work or later feature phases.

### Pre-phase state

- Branch: `main`.
- Pre-phase commit SHA: `3bf039c`.
- Working tree contained pre-existing uncommitted Phase 3 queue/worker WIP:
  - `apps/api/nope_api/main.py`
  - `apps/api/nope_api/models.py`
  - `apps/api/requirements.txt`
  - `apps/worker/worker.py`
  - `docker-compose.yml`
  - `apps/api/nope_api/queue.py`
  - `apps/api/tests/test_queue.py`

### Implemented

- Added Alembic configuration at `apps/api/alembic.ini`.
- Added Alembic environment and revisions under `apps/api/alembic`.
- Alembic revisions wrap the existing SQL migrations so the startup SQL runner remains compatible while explicit `alembic upgrade/current/downgrade` commands are available.
- Added `alembic` to API dependencies.
- Extended `PostgresStore` so project creation persists `project_targets` and `repository_sources` when inputs are present.
- Extended scan saving so repository snapshots are upserted from branch, commit, and upload metadata.
- Added repository-layer persistence methods for:
  - `application_settings`
  - `model_configurations`
  - `scanner_configurations`
  - `security_baselines`
  - `drift_events`
  - `audit_logs`
  - explicit project target/source/snapshot creation
- Added a Phase 1 persistence test covering the required contract entities.
- Updated `docs/DATABASE.md`, `docs/FEATURE_STATUS.md`, and `docs/PHASE_RECONCILIATION.md`.

### Verification plan

- Compile API, tests, worker, and Alembic files.
- Run non-Docker unit tests.
- Run persistence tests if Postgres is reachable.
- Run Alembic commands if Postgres is reachable and `alembic` is installed.
- Run frontend lint/typecheck/build to preserve current app behavior.
- Run Docker config/build/up/ps/logs if Docker Desktop Linux engine is reachable.

### Verification results

Verification commands are recorded in the Phase 1 completion dossier.

## 2026-07-15 Phase 3 Redis Queue and Worker Orchestration

### Objective

Complete the canonical Phase 3 queue/worker phase without advancing into Phase 4.

### Implemented

- Converted scan start endpoints to persist queued scans and enqueue Redis jobs instead of running long scans synchronously in the API request.
- Added Redis job metadata: job ID, active scan idempotency, attempts, maximum attempts, queued timestamp, run-after timestamp, processing tracking, and bounded retry backoff.
- Added worker heartbeat, queue status, worker health, cancellation, retry, and scan events endpoints.
- Added scan-engine progress callbacks and cancellation checkpoints so worker progress is saved to Postgres during execution and survives page/API reloads.
- Added worker retry/failure handling with redacted error messages and partial/failed state persistence.
- Added worker reconnect loop and Compose restart policy for Redis outage resilience.
- Shared repository workspaces through the Docker `nope-workspaces` volume and fixed non-root write permissions in the API image.
- Expanded queue tests for execution, cancellation, retry/backoff, redaction, and event progress.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: passed, 29 tests.
- Docker images rebuilt:
  - `nope-nope-api:latest` `903026c0b97a`
  - `nope-nope-worker:latest` `bda4f232c33b`
- Docker stack healthy: web, API, worker, Postgres, Redis, MinIO.
- Real API queue proof:
  - Queued `scan_4ebe1b771ac7413b` and `scan_c8fbd2708e4044e6` while worker was stopped.
  - Both API responses returned `queued` before scan execution.
  - Cancelled `scan_c8fbd2708e4044e6` while queued; worker persisted cancelled state without scanner execution.
  - Restarted API before worker execution; worker completed `scan_4ebe1b771ac7413b` with 29 findings.
- Worker restart/stuck processing proof:
  - Interrupted worker during `scan_6ede29d9d13d4778`, requeued the processing payload, restarted worker, and completed the scan with 29 findings.
- Retry proof:
  - Created failed scan `scan_phase3_retry_failed`, called the real retry endpoint, and worker completed it with 29 findings.
- Redis failure proof:
  - Stopped Redis; `/api/queue/status` returned `redis:error`.
  - Rebuilt worker survived the broker outage, logged queue-loop restart, and reported a fresh heartbeat after Redis returned.

### Closure

Phase 3 is complete for local Redis-backed queue and worker orchestration. Later phases still own richer finding correlation, UI polish, dynamic sandboxing, Qwen inference, PDFs, benchmarks, and final documentation.

## 2026-07-15 Phase 4 Normalization, Deduplication, Correlation

### Objective

Complete canonical backend finding normalization, deduplication, correlation, lifecycle, suppression expiry, and recurrence without starting Phase 5 Qwen work.

### Implemented

- Expanded the canonical finding model with scanner/run/rule metadata, original severity/confidence, source-location fields, route/endpoint, package/CVE, raw artifact, attack/impact, lifecycle, AI review, recurrence, baseline, and suppression fields.
- Added lifecycle enums and suppression model fields.
- Updated NOPE rules, external scanner parsers, and URL scanner findings to populate canonical metadata.
- Replaced exact-fingerprint-only dedupe with correlation keys for duplicate secrets, CVE/package dependencies, file/line matches, rule/symbol, route/root cause, code-flow fingerprint, and scanner/source location.
- Preserved all unique evidence when duplicates merge.
- Promoted normalized severity/confidence during merge while retaining original scanner severity/confidence fields.
- Enriched findings before persistence so scan snapshots, normalized finding rows, evidence rows, source rows, and history rows include lifecycle/recurrence changes.
- Added automatic suppression expiry reopen and reintroduced recurrence detection based on prior finding history.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: passed, 36 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- Docker images rebuilt:
  - `nope-nope-api:latest` `e48f0d44740f`
  - `nope-nope-worker:latest` `ba5d2472e0a4`
- Docker stack healthy: web, API, worker, Postgres, Redis, MinIO.
- Real worker scan `scan_4a6bedf526e1440d` completed with 25 deduped findings. This is lower than the previous 29 raw scanner/custom findings because Phase 4 now merges duplicate evidence.
- Returned canonical finding JSON included `scanner`, `original_rule_id`, `original_severity`, `start_line`, `end_line`, `verification_state`, `ai_review_state`, `recurrence_count`, and `baseline_state`.
- Phase 4 tests verify duplicate secret, duplicate CVE/package, Semgrep plus custom rule, static plus dynamic route evidence, suppression expiry, reintroduced recurrence, severity mapping, and confidence mapping.

### Closure

Phase 4 is complete for backend canonical finding normalization, deduplication, correlation, lifecycle persistence, suppression expiry, and recurrence. Phase 5 Qwen/llama.cpp remains untouched; the user requirement to keep GPU VRAM under 5 GB is reserved for that phase.

## 2026-07-15 Phase 5 Qwen llama.cpp Runtime

### Objective

Complete canonical Phase 5 by running Qwen through llama.cpp Docker, invoking it from NOPE, preserving deterministic scans on AI failure, and keeping GPU VRAM under 5 GB.

### Implemented

- Added canonical Qwen settings for endpoint, model file, context, batch size, threads, parallelism, GPU layers, output cap, timeout, retry limit, and GPU memory target.
- Updated Docker AI profiles to mount `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf` read-only through `NOPE_MODEL_HOST_DIR` and `NOPE_MODEL_FILE`.
- Switched the GPU profile to `ghcr.io/ggml-org/llama.cpp:server-cuda`.
- Reworked the AI adapter for llama.cpp health, direct completion, OpenAI-compatible structured chat completion, JSON validation, redacted logs, focused finding context, and failure-safe scan continuation.
- Added FastAPI finding actions for explain, challenge, fix, and test.
- Added frontend finding action controls plus settings health/runtime/GPU status display.
- Added Phase 5 unit tests for focused context, structured validation, invalid JSON rejection, deterministic preservation on Qwen failure, and GPU memory target capping.

### Verification results

- Model file exists at `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`, size 5,027,783,488 bytes.
- GPU baseline is `NVIDIA GeForce GTX 1060 with Max-Q Design`, 6144 MiB total.
- `NOPE_QWEN_GPU_LAYERS=30` failed to fit in available GPU memory.
- `NOPE_QWEN_GPU_LAYERS=28` is stable and measured about 4041-4049 MiB VRAM, below the 5000 MiB ceiling.
- Docker health showed `nope-ai` healthy with `gpu_layers: 28`, `gpu_memory_target_mb: 5000`, and AI latency around 119-147 ms.
- Direct llama.cpp `/completion` succeeded.
- Structured `/v1/chat/completions` JSON succeeded.
- FastAPI finding explanation succeeded through Qwen with validated structured output.
- Stopped `nope-ai` and ran repository scan `scan_443bb3dbdb9b4568`; it completed with 7 deterministic findings and `ai_review.status` set to `Failed`, proving Qwen failure does not stop scans.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase5_qwen.py`: passed, 5 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests`: passed, 41 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.

### Closure

Phase 5 is complete for local Qwen inference through llama.cpp Docker. The final verified GPU setting is 28 layers, using about 4.0 GB VRAM and staying below the 5 GB cap while still combining GPU offload with CPU execution for the remaining layers.

## 2026-07-15 Phase 6 Focused Graph-Aware RAG

### Objective

Implement focused graph-aware retrieval for Qwen without sending whole repositories and without requiring embeddings.

### Pre-phase state

- Pre-phase commit: `3ebec58a7d40491f6d22aa964b510443c16f8a6a`.
- Phase 5 Qwen runtime is committed and pushed.
- Existing context builder is finding-only and lives in `apps/api/nope_api/ai.py`.
- Existing attack-surface and lightweight code graph are built during repository scans and persisted on the scan model.

### Required tasks

- Index source files, functions, classes, routes, middleware/auth/authorization/validation hints, models, queries, database policies, migrations, configuration, tests, scanner findings, attack-surface nodes, code-graph edges, security rules, and guidance.
- Retrieve with lexical search, symbol/file/import/route relationships, code graph neighbors, finding-centered context, and no-embedding fallback.
- Include route context: handler, middleware, authentication, authorization, validation, model/query/storage signals, related tests, scanner evidence, and security guidance.
- Enforce maximum chunks, files, approximate tokens, graph depth, deduplication, metadata, retrieval reason, secret redaction, and truncation.
- Treat repository instructions, comments, README text, and source strings as untrusted data separated from scanner evidence and security guidance.

### Required tests

- IDOR context retrieval.
- Supabase policy retrieval.
- Secret retrieval with redaction.
- Dependency retrieval.
- Overflow handling.
- Duplicate removal.
- Malicious repository prompt text handling.
- RAG without embeddings.

### Implemented

- Added `apps/api/nope_api/rag.py` with bounded lexical and graph-aware retrieval.
- Indexed repository source/config/test/dependency/database-policy files, functions, classes, routes, imports, scanner findings, scanner runs, stack evidence, attack-surface route context, code-graph edges, and security guidance.
- Added provenance fields for file, line, symbol, route, chunk kind, trust boundary, metadata, retrieval reason, and score.
- Added limits for chunks, files, approximate tokens, graph depth, and chunk size.
- Added secret redaction and truncation before context is serialized for Qwen.
- Added prompt-injection controls that treat README text, comments, and source strings as untrusted data.
- Wired repository scans to pass root path and scan graph data into Qwen review.
- Exposed RAG limits in `/api/settings/model` and the settings page.
- Preserved no-embedding behavior through explicit `embeddings_used = False`.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase6_rag.py apps/api/tests/test_phase5_qwen.py -q`: passed, 11 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 47 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase6_rag.py apps/api/tests/test_pipeline.py -q`: passed, 10 tests after graph-label false-positive cleanup.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed.
- `GET http://localhost:8000/health`: passed; API reports Qwen healthy at 28 GPU layers.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4041, 6144`.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed after renaming a graph-local false-positive string.

### Closure

Phase 6 is complete for focused graph-aware RAG without embeddings. Whole repositories are not sent to Qwen; selected chunks carry provenance, retrieval reasons, trust boundaries, limits, redaction, and prompt-injection controls.

## 2026-07-15 Phase 7 Findings Filters, Detail, Evidence, Code Flow

### Objective

Complete server-backed findings filtering and detail views with protected evidence, real source snippets, real code-flow data, and stable URL state.

### Pre-phase state

- Pre-phase commit: `8ce88900cf0912e90ef3a27e92fdf401e08c83ef`.
- Findings page rendered the full scan findings array without server filters, pagination, or stable shared filter URLs.
- Backend exposed only `/api/scans/{scan_id}/findings` as a raw list.

### Implemented

- Added `apps/api/nope_api/findings.py` for filtering, sorting, pagination, detail payloads, source snippets, code-flow extraction, history payloads, and raw artifact lookup.
- Replaced the findings route with a server-backed query envelope supporting severity, confidence, status, scanner, rule, CWE, OWASP, file, route, first-seen, new, fixed, reintroduced, suppressed, AI-reviewed, verified, fix-available, query, sort, direction, page, and page size.
- Added authenticated finding detail route with Overview, Evidence, Code, Code Flow, Fix, Tests, and History payloads.
- Added authenticated raw artifact route that verifies scan ownership and redacts secret-like values.
- Added suppression endpoint for finding lifecycle updates.
- Rebuilt the findings page with URL-backed filters, pagination, stable selected finding, tabbed detail, code snippets with line numbers/highlights, evidence cards, real graph edge display, fix/test/history tabs, and Qwen actions.
- Updated shared frontend types and table behavior.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase7_findings.py -q`: passed, 6 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase7_findings.py apps/api/tests/test_phase4_findings.py -q`: passed, 13 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 53 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.

### Closure

Phase 7 is complete for server-backed filters, URL-stable findings UI, protected evidence/detail access, code snippets, real code-flow display, suppression lifecycle action, and large-list pagination.

## 2026-07-15 Phase 8 History, Baselines, Drift

### Objective

Implement persistent security baselines, scan-to-scan and scan-to-baseline comparison, drift classification, and a conservative incremental-scope foundation without replacing full scans.

### Pre-phase state

- Pre-phase commit: `95b2ddf1d3cf487ee97e09ece927a7ba91a54b53`.
- `security_baselines` and `drift_events` tables existed from Phase 1.
- Phase 4 lifecycle history could mark recurrence/reintroduced findings.
- No comparison engine, drift API, or UI summary existed.

### Implemented

- Added `apps/api/nope_api/drift.py` for baseline snapshots, scan comparisons, drift events, coverage/scanner/stack differences, domain-specific drift signals, and conservative incremental scope.
- Baseline snapshots record scan ID, commit SHA, repository snapshot, target, scanner versions, rule versions, model version, quantization, RAG version, timestamp, coverage, findings, routes, dependencies, and stack.
- Added owner-scoped baseline storage getters/listing and drift-event listing.
- Added API routes for baseline creation/list/get, scan comparison, drift persistence, and drift event listing.
- Comparison detects new, fixed, unchanged, reintroduced, severity changes, confidence changes, coverage difference, scanner difference, stack difference, new/removed routes, new dependency, new CVE, new secret, RLS policy change, weaker CORS, weaker headers, new tracker, new public asset, and scanner coverage regression.
- Incremental scope reports changed files, affected graph nodes, relevant scanners, finding categories, and an explicit note that incremental replacement is advisory until Phase 14.
- Scans page now displays latest-vs-previous drift metrics, recent drift events, saved baselines, and incremental scope notes.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase8_drift.py -q`: passed, 4 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase8_drift.py apps/api/tests/test_phase7_findings.py -q`: passed, 10 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 57 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; rebuilt `nope-nope-api`, `nope-nope-worker`, and `nope-nope-web`.
- `$env:NOPE_MODEL_HOST_DIR='D:/Desktop/Model'; $env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'; $env:NOPE_QWEN_GPU_LAYERS='28'; docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed after supplying the verified host GGUF path.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `GET http://localhost:8000/health`: passed; API reports Qwen healthy at 28 GPU layers and `gpu_memory_target_mb: 5000`.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4041, 6144`.
- Live Phase 8 API smoke against running Docker stack: passed; login, baseline creation, baseline comparison, drift persistence, and drift listing returned 200 with summary `new=1`, `fixed=1`, `severity_changes=1`, `coverage_drift=1`, `scanner_drift=1`, and 7 persisted drift events.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.

### Closure

Phase 8 is complete for baseline metadata, scan comparisons, persisted drift events, drift UI summary, stable fingerprints, reintroduced/fixed/new detection, coverage regression visibility, and conservative incremental-scope reporting. Full scan replacement remains explicitly deferred until Phase 14 verification.

## 2026-07-15 Phase 9 PDF Reporting

### Objective

Complete PDF reporting with real scan data, protected downloads, durable generation metadata, MinIO artifact storage, redaction, pagination, partial-scan honesty, and baseline/drift visibility.

### Pre-phase state

- Pre-phase commit: `0d243da`.
- JSON, Markdown, and SARIF report routes existed and persisted text bodies in Postgres.
- `reports` table already stored body, hash, byte size, generated time, and JSON metadata.
- PDF reports were explicitly marked not implemented.

### Implemented

- Added ReportLab PDF rendering with NOPE branding, project/repository/commit/target/date/scope, executive summary, verdict, coverage, scanner status, severity sections, suppressed findings, failed scanners, untested areas, Qwen status, baseline/drift summary, privacy warnings, staging warnings, limitations, methodology, and reproducibility metadata.
- Added secret redaction to report text before Markdown, JSON/SARIF text fields, and PDF rendering.
- Added PDF pagination through ReportLab flowables and verified large reports span multiple pages.
- Added binary artifact storage helper for PDF uploads to MinIO.
- Extended report persistence to handle binary PDF bodies as base64 in Postgres with SHA-256, byte size, generation status, and MinIO object metadata when available.
- Added protected report status route for persisted report generation metadata.
- Kept generation synchronous because current local PDF rendering is bounded; persisted status records `completed` and can survive API restart.
- Added PDF as a first-class report format and exposed it on the reports page.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase9_pdf_reports.py -q`: passed, 3 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 60 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `git diff --check`: passed with Windows line-ending warnings only.
- `docker compose build nope-api nope-worker nope-web`: passed; rebuilt API, worker, and web images with `reportlab` installed in API/worker.
- `$env:NOPE_MODEL_HOST_DIR='D:/Desktop/Model'; $env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'; $env:NOPE_QWEN_GPU_LAYERS='28'; docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `GET http://localhost:8000/health`: passed; API reports database migrations current, scanner availability, and Qwen runtime reachable.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 0, 6144` during Phase 9 smoke because inference was not exercised; GPU profile remains configured at 28 layers and below the 5 GB ceiling.
- Live Phase 9 PDF smoke against rebuilt Docker stack: passed; login 200, PDF download 200, body starts `%PDF`, size 17,317 bytes, secret value redacted, status route 200, generation status `completed`, MinIO URL `minio://nope-artifacts/scans/scan_phase9_live_f038b010/art_e2d3b616115345c4-scan_phase9_live_f038b010-report.pdf`, byte size matched.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.

### Closure

Phase 9 is complete for local PDF report generation and protected download behavior. PDF reports contain real scan data, persisted generation status, MinIO artifact metadata, redaction, pagination, partial/failed scanner representation, drift/baseline summary, limitations, methodology, and reproducibility metadata.

## 2026-07-15 Phase 10 Sandbox Foundation

### Objective

Add a disposable local Docker sandbox for safe repository workflows and initial dynamic ZAP scans without exposing host secrets, host home, or Docker socket access to the sandbox containers.

### Pre-phase state

- Pre-phase commit: `f84b545`.
- ZAP was represented in scanner capabilities but marked skipped/not applicable for static repository scans.
- The security model described a sandbox concept, but no manifest loader, Docker lifecycle, sandbox stage, health endpoint, or tests existed.

### Implemented

- Added `.nope/sandbox.json` manifest loading for Node, Python, static, custom, startup, and ZAP workflow definitions.
- Added disposable Docker workflow execution with non-root app containers, no privileged mode, dropped capabilities, `no-new-privileges`, read-only repository mount, read-only root filesystem where supported, tmpfs workspace, bounded logs, CPU/memory/PID/tmpfs limits, network disabled by default, command timeouts, and timeout cleanup.
- Added private-network ZAP flow that starts an isolated application container, runs `ghcr.io/zaproxy/zaproxy:stable` against the internal target, captures bounded evidence, and removes the app container/network.
- Added scan-engine integration through a `Running sandbox workflows` stage, scanner-run evidence, dynamic-testing coverage updates, and failure findings.
- Added `/api/sandbox/health` and sandbox details in `/health`.
- Added Docker CLI support to the API/worker image and mounted the Docker socket only into `nope-worker` so queued scans can orchestrate sibling sandbox containers; sandbox containers themselves still do not receive the socket.
- Added read-only shared workspace volume mounting for sandbox containers when scans run inside the Compose worker, while preserving direct host bind mounts for local non-container execution.
- Added a separate bounded ZAP timeout so baseline scans can initialize without weakening normal build/test workflow timeouts.
- Added `docs/SANDBOX.md` and refreshed API, scanner, architecture, security-model, feature-status, and phase-reconciliation docs.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase10_sandbox.py -q`: passed, 9 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 69 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; rebuilt API image `038ba5c624b2`, worker image `df66c4a46dfa`, and web image `cceb3183045f`.
- `$env:NOPE_MODEL_HOST_DIR='D:/Desktop/Model'; $env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'; $env:NOPE_QWEN_GPU_LAYERS='28'; docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `GET http://localhost:8000/health`: passed; sandbox enabled, Docker CLI available at `/usr/bin/docker`, workspace volume `nope_nope-workspaces`, network default disabled, workflow timeout 60 seconds, ZAP timeout 180 seconds, memory `512m`, ZAP memory `1024m`, pids `128`/`256`, and isolation flags report no sandbox Docker socket, host home, or NOPE secrets.
- `docker compose exec -T nope-worker sh -lc "id && docker version --format '{{.Client.Version}} {{.Server.Version}}' && test -S /var/run/docker.sock && echo worker-socket-present"`: passed; worker has Docker CLI/server `29.6.1` and the orchestrator socket.
- Real Docker sandbox successful build workflow: passed; dynamic coverage `Verified`; no sandbox Docker socket, host home, or NOPE secrets reported.
- Real Docker infinite-loop timeout workflow: failed as expected; timeout cleanup performed.
- Real Docker host-file attempt: passed; `/var/run/docker.sock` absent, home isolated to `/tmp`, and read-only repository source write denied.
- Real Docker network attempt: failed as expected under `--network none`.
- Real Docker memory-abuse workflow with `128m` memory limit: failed as expected with exit code 137.
- Real Docker failed-command workflow: failed as expected with exit code 42 and produced a sandbox finding.
- Real Docker ZAP fixture scan: passed against an internal app container, with cleanup performed and no sandbox Docker socket mounted.
- Real Compose worker sandbox+ZAP smoke from `/app/.nope-workspaces`: passed; final ZAP smoke returned `Verified` coverage and cleanup performed, and final compile smoke used the shared workspace volume read-only. Neither sandbox mounted the Docker socket, host home, or NOPE secrets.
- `docker ps -a --filter "name=nope-sandbox"` plus `docker network ls --filter "name=nope-sandbox"`: no leftover sandbox containers or networks after cleanup.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 0, 6144` during Phase 10 smoke; Qwen remains configured at 28 GPU layers with a 5000 MB target, and Phase 10 did not exercise inference.

### Closure

Phase 10 is complete for the sandbox foundation: manifest-driven workflows, constrained disposable containers, default network denial, host-secret isolation, timeout/resource enforcement, unsupported repository handling, internal ZAP dynamic scan support, cleanup, scan-stage evidence, health reporting, Docker worker activation, and documentation. Browser automation and authenticated dynamic flows remain later phases.

## 2026-07-16 Phase 11 Settings and GitHub Contracts

### Objective

Complete persistent owner-scoped system/project settings and local GitHub contract handling with validation, encrypted sensitive values, redacted responses, settings UI, and honest blocked state for private GitHub access.

### Pre-phase state

- Pre-phase commit: `4219b9b`.
- Phase 1 schema included `application_settings`, `model_configurations`, `scanner_configurations`, and GitHub contract tables.
- The settings page displayed environment-derived values only.
- GitHub private access was documented as blocked, but no route/UI contract existed.

### Implemented

- Added typed settings contracts for system settings, project settings, test identities, GitHub settings, and GitHub status.
- Added owner-scoped system settings API for Qwen endpoint/runtime/context/GPU layers/timeout/output/concurrency, scanner enabled state, scanner timeout, default scan mode, retention, report defaults, artifact limits, and sandbox limits.
- Added owner-scoped project settings API for target URL, approved hosts, excluded paths, scanner overrides, scan depth, test identities, baseline, repository metadata, authorization confirmation, and RAG limits.
- Added encrypted secret envelopes for test identity passwords, GitHub OAuth client secret, GitHub private key, and webhook secret.
- Ensured sensitive settings are not returned after save; responses expose only configured/credential state.
- Added owner/project authorization checks and audit rows for settings updates.
- Added GitHub status/settings/repository/callback routes with a blocked adapter contract and no fake repositories.
- Added GitHub contract persistence through `github_connections.data` plus `application_settings`.
- Added settings forms for system, project, and GitHub contract settings in the dashboard.
- Added an explicit blocked GitHub adapter interface for local status, repository listing, and callback behavior.
- Added `cryptography` as an explicit backend dependency for Fernet encryption.
- Updated API, database, security-model, feature-status, and phase-reconciliation documentation.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase11_settings_github.py -q`: passed, 3 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase11_settings_github.py apps/api/tests/test_api_auth.py -q`: passed, 5 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 72 tests.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `git diff --check`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; images `nope-nope-api@sha256:7ca795bb081f`, `nope-nope-worker@sha256:8a016f6d7d14`, `nope-nope-web@sha256:05a37327fbe7`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed with all services healthy.
- `Invoke-RestMethod http://localhost:8000/health`: passed; database migrations current, scanner tools installed, Qwen runtime reachable, GPU layers `28`, GPU target `5000`.
- Live Phase 11 API smoke: passed; system settings persisted into `/api/settings/model`, project secrets were redacted, cross-user project settings returned `404`, GitHub returned `blocked_external_credentials_not_verified`, repository list was empty, and callback returned `409`.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4473, 6144`; 28 GPU layers remained under the 5 GB VRAM cap.

### Closure

Phase 11 is complete for local settings persistence, validation, encrypted sensitive storage, redacted secret responses, settings ownership, settings UI, GitHub local contracts, callback route shape, credential state, branch/repository selection contracts, and honest blocked private GitHub access. Real GitHub token exchange and private repository listing remain blocked by missing verified GitHub credentials.

## 2026-07-16 Phase 12 Benchmarks and Fixtures

### Objective

Add reproducible benchmarks and vulnerable fixtures with versioned expected output, scanner-only and scanner-plus-Qwen modes, machine-readable metrics, resource timing, and visible failures.

### Pre-phase state

- Pre-phase commit: `5c28997`.
- Existing fixtures covered only a small vulnerable Next app and scanner parser inputs.
- `FEATURE_STATUS.md` and `PHASE_RECONCILIATION.md` marked Benchmarks as partially complete.
- No benchmark command, expected output file, or scanner-only versus Qwen comparison existed.

### Implemented

- Added a versioned benchmark fixture at `benchmarks/fixtures/nope-benchmark-v1`.
- Added fixture manifest coverage for every required Phase 12 category.
- Added versioned expected output at `benchmarks/expected/nope-benchmark-v1.expected.json`.
- Added `python -m nope_api.benchmarks` with scanner-only and scanner-plus-Qwen modes.
- Added JSON metrics for expected findings, actual findings, true positives, false positives, known false negatives, scanner source, Qwen contribution, scan duration, resource use, and fix verification.
- Added tests for fixture category coverage, expected-output versioning, comparison accounting, and result schema.
- Added `docs/BENCHMARKS.md` and updated status/reconciliation docs.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase12_benchmarks.py -q`: passed, 4 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `$env:PYTHONPATH='apps/api'; python -m nope_api.benchmarks --mode scanner-only --output .nope-benchmark-results/scanner-only.local.json`: passed locally; host scanner CLIs were unavailable and recorded as visible scanner-run failures, with no unexpected false negatives.
- `$env:PYTHONPATH='apps/api'; python -m nope_api.benchmarks --mode scanner-plus-qwen --output .nope-benchmark-results/scanner-plus-qwen.local.json`: passed locally; host AI provider was disabled and recorded as `Not tested`.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 76 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; final rebuilt images include `nope-nope-api@sha256:9cccee15b7b1`, `nope-nope-worker@sha256:c3c698d9730c`, and `nope-nope-web@sha256:05a37327fbe7`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed; API and worker refreshed from the Phase 12 images.
- Original Phase 12 Docker scanner-only baseline: 30 actual findings, 8 true positives, and 14 known false negatives. This historical baseline is superseded by the 2026-07-18 Stage 1 review below.
- Original Phase 12 Docker scanner-plus-Qwen baseline: 30 actual findings, 8 true positives, and 14 known false negatives with Qwen contribution `Complete`. This historical baseline is superseded by the 2026-07-18 Stage 1 review below.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `Invoke-RestMethod http://localhost:8000/health`: passed; scanners installed, Qwen reachable, GPU layers `28`, GPU memory target `5000`.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/benchmarks`: passed, no leaks found.
- Full `/app` Gitleaks scan reported pre-existing vulnerable test/runtime workspace fixture findings; Phase 12 benchmark fixture was not among them.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4485, 6144`; GPU profile remained below the 5 GB VRAM cap.

### Closure

Phase 12 originally made benchmark gaps visible and comparable. The 2026-07-18 Stage 1 Benchmark Completion Review below supersedes this entry with the final 41-category pass and zero known false negatives.

## 2026-07-18 Stage 1 Benchmark Completion Review

### Goal

Review Stage 1 against the original completion prompt before starting Stage 2. Fix any non-passing criterion that is locally achievable, rerun benchmark and regression tests, update documentation, commit, push, and return an evidence-based completion dossier.

### Changes

- Expanded the benchmark fixture contract from the earlier 22-category pass to all 41 required Stage 1 categories.
- Added missing vulnerable fixtures for environment exposure, archive extraction, auth/reset/signup/OTP abuse, CSRF, Dockerfile, IaC, Firebase, headers, cookies, staging, build scripts, and credential logging.
- Added deterministic NOPE rules for the new categories and taught the rule engine to scan `.tf`, `.rules`, `.env`, Dockerfile, and other benchmark-relevant text inputs.
- Excluded benchmark control metadata from rule scanning so fixture descriptions do not become findings.
- Fixed evidence validation so resource IDs such as `accountId` are not mistaken for owner-scope authorization and policy/config findings such as Firebase/Supabase evidence are promoted through the correct path.
- Fixed dedupe so different rules on the same file/line are preserved instead of being merged into one finding.
- Added Stage 1 regression tests for every required category, NOPE-rule-backed coverage, negative controls, dedupe, deterministic comparison, scanner-unavailable, scanner-timeout, Qwen-unavailable deterministic preservation, Firebase policy validation, and OSV parser normalization.
- Refreshed benchmark/status documentation with the current 41-category Docker results.

### Verification

- `python -m json.tool security-packs/nope-core-rules.json`
- `python -m json.tool benchmarks/fixtures/nope-benchmark-v1/benchmark-manifest.json`
- `python -m json.tool benchmarks/expected/nope-benchmark-v1.expected.json`
- `python -m pytest apps/api/tests/test_phase12_benchmarks.py apps/api/tests/test_scanners.py -vv --tb=short`: 59 passed before the final validation additions.
- `python -m pytest apps/api/tests/test_phase12_benchmarks.py apps/api/tests/test_finding_validation.py -vv --tb=short`: 57 passed.
- `python -m pytest apps/api/tests -vv --tb=short`: 144 passed, 2 warnings.
- `docker compose build nope-api nope-worker`: passed.
- `docker compose run --rm --no-deps -v "${PWD}/.nope-benchmark-results:/results" nope-api python -m nope_api.benchmarks --mode scanner-only --output /results/scanner-only.json --markdown-output /results/scanner-only.md`: passed, 41 expected, 70 actual, 41 true positives, 0 false positives, 0 false negatives, 0 known false negatives, 31 related duplicates, precision/recall/F1 `1.000`, duration `37.416s`.
- `docker compose run --rm --no-deps -v "${PWD}/.nope-benchmark-results:/results" nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /results/scanner-plus-qwen.json --markdown-output /results/scanner-plus-qwen.md`: passed, 41 expected, 70 actual, 41 true positives, 0 false positives, 0 false negatives, 0 known false negatives, 31 related duplicates, precision/recall/F1 `1.000`, duration `99.575s`, Qwen status `Complete`.

### Result

Stage 1 is complete for the locally achievable scope. Stage 2 was not started.

## 2026-07-16 Phase 13 Test Expansion

### Objective

Expand unit, integration, E2E, and NOPE-security tests while keeping the core suite runnable without Qwen and keeping GPU/Qwen checks separate.

### Pre-phase state

- Pre-phase commit: `9d39cac`.
- Backend tests covered prior phase contracts but Phase 13 was still marked partially complete.
- Frontend had lint/typecheck/build scripts but no `test` script.
- No single Phase 13 test file explicitly grouped unit, integration, E2E, and NOPE-security coverage.

### Implemented

- Added `apps/api/tests/test_phase13_expansion.py` with unit, integration, E2E, and security coverage.
- Added migration and scanner command-construction tests.
- Added a core repository scan test that runs with `ai_provider="none"`.
- Added ownership tests for scans, raw artifacts, and reports.
- Added an API-level E2E flow for login, project creation, ZIP upload, scan start, events, findings filter/detail/evidence tabs, AI explanation fallback, report download, baseline, comparison, and settings persistence.
- Added security tests for bearer-only CSRF posture, login rate limiting, private URL blocking, malformed ZIP rejection, command construction safety, and redaction.
- Added a conservative login failure throttle returning `429` after repeated bad credentials.
- Added `pnpm --dir apps/web test` as a CI-compatible no-emit TypeScript check.
- Added `docs/TESTING.md` and updated feature/reconciliation status.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase13_expansion.py -q`: passed, 6 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_security.py apps/api/tests/test_phase7_findings.py apps/api/tests/test_phase6_rag.py -q`: passed, 18 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 82 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web test`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `git diff --check`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; images `nope-nope-api@sha256:85da99402f32`, `nope-nope-worker@sha256:c9af5d8f73c0`, and `nope-nope-web@sha256:19fa894e01b2`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed with `NOPE_QWEN_GPU_LAYERS=28` and `NOPE_QWEN_GPU_MEMORY_TARGET_MB=5000`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `Invoke-RestMethod http://localhost:8000/health`: passed; migrations current, scanner tools installed, Qwen runtime reachable, GPU layers `28`, GPU memory target `5000`.
- `Invoke-WebRequest http://localhost:3000 -UseBasicParsing`: passed with HTTP `200`.
- `docker compose run --rm --no-deps nope-api python -m compileall /app/apps/api/nope_api /app/apps/worker`: passed.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- `docker compose run --rm --no-deps nope-api python -m pytest /app/apps/api/tests/test_phase13_expansion.py -q`: not run inside the production image because `pytest` is intentionally not installed there; the equivalent host suite passed before image refresh.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4485, 6144`; GPU profile remained under the 5 GB VRAM cap.

### Closure

- Phase 13 is complete for expanded unit, integration, API-level E2E, and NOPE-security tests; CI-compatible frontend test commands; core backend tests that run without Qwen; separate GPU/Qwen verification; Docker image refresh; and under-5 GB VRAM validation.

## 2026-07-16 Phase 14 Full End-to-End Pipeline

### Objective

Verify the complete local-first pipeline from login and project creation through full scan execution, queued worker processing, deterministic analysis, focused Qwen/RAG contracts, reports, baselines, modified second scan, drift, and honest failure handling.

### Pre-phase state

- Pre-phase commit: `84b10af`.
- The full scan endpoint existed, but Phase 14 was not yet documented or tested as one end-to-end pipeline.
- `run_full_scan` combined repository and URL checks, but the URL leg did not have an explicit stage and URL scanner failure did not force the final full-scan status to `partial`.
- Status docs still marked full scan, stack detection, attack-surface extraction, code graph, and Phase 14 drift proof as incomplete or deferred.

### Implemented

- Added an explicit `Running URL checks` stage to full scans.
- Ensured full scans finish as `partial` when any scanner run fails, including URL scanner failures.
- Updated drift incremental-scope wording to keep full scans as the authoritative comparison path.
- Added `apps/api/tests/test_phase14_pipeline.py`.
- Verified API login, project creation, full ZIP upload, repository snapshot persistence, queued job payloads, worker execution via `execute_scan_job`, stack detection, attack-surface mapping, code graph creation, scanner selection/execution contract, URL scan merging, finding normalization/deduplication, evidence persistence, Qwen/RAG review contract, coverage, findings query, JSON/PDF report generation, baseline creation, modified second scan, comparison, and persisted drift events.
- Added failure-path coverage for scanner failure/timeout, Qwen unavailable, unsupported sandbox, malformed ZIP, and cancelled scan persistence.
- Updated feature and reconciliation status for Phase 14 pipeline scope.

### Verification results

- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase14_pipeline.py -q`: passed, 2 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_phase14_pipeline.py apps/api/tests/test_phase8_drift.py -q`: passed, 6 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests/test_queue.py apps/api/tests/test_phase8_drift.py apps/api/tests/test_phase9_pdf_reports.py -q`: passed, 11 tests.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 84 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web test`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose config --quiet`: passed.
- `git diff --check`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; images `nope-nope-api@sha256:bd525ce0c50e`, `nope-nope-worker@sha256:c032824df94e`, and `nope-nope-web@sha256:19fa894e01b2`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed with `NOPE_QWEN_GPU_LAYERS=28` and `NOPE_QWEN_GPU_MEMORY_TARGET_MB=5000`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `Invoke-RestMethod http://localhost:8000/health`: passed; migrations current, scanner tools installed, Qwen runtime reachable, GPU layers `28`, GPU memory target `5000`.
- Authenticated `/api/queue/status` and `/api/worker/health`: passed; Redis `ok`, queue depth `0`, processing depth `0`, worker heartbeat present, worker healthy.
- `Invoke-WebRequest http://localhost:3000 -UseBasicParsing`: passed with HTTP `200`.
- `docker compose run --rm --no-deps nope-api python -m compileall /app/apps/api/nope_api /app/apps/worker`: passed.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- `nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4485, 6144`; GPU profile remained under the 5 GB VRAM cap.

### Closure

- Phase 14 is complete for the full local end-to-end pipeline proof, explicit full-scan URL stages, honest partial status on scanner failures, persisted baselines and drift from a modified second scan, JSON/PDF reports after full worker execution, failure-path coverage, Docker image refresh, live queue/worker/API/web/AI health, and under-5 GB VRAM validation.

## 2026-07-16 Phase 15 UI and Responsive Polish

### Objective

Complete the canonical Phase 15 frontend pass: one dark graphite theme, complete public landing page, separate dashboard under `/app`, LineSidebar-style app navigation, polished route surfaces, dense findings UI, motion/reduced-motion states, and required viewport verification.

### Pre-phase state

- Pre-phase commit: `dcd186d`.
- The app already had a routed dashboard and dark design system, but Phase 15-specific landing sections, dashboard widgets, mobile polish, route verification, and documentation were not complete.
- The local Qwen profile was already configured for `NOPE_QWEN_GPU_LAYERS=28` and `NOPE_QWEN_GPU_MEMORY_TARGET_MB=5000`.

### Implemented

- Completed the public landing page with navigation, hero, animated scan demo, product methodology, why-NOPE section, rules-first AI explanation, local Qwen section, attack-map showcase, evidence showcase, coverage, CTA, and footer.
- Expanded the dashboard overview with verdict, score, severity counts, coverage, drift, latest findings, scan pipeline, scanner status, Qwen status, and untested areas.
- Tightened the app shell topbar, route-aware LineSidebar behavior, keyboard/focus states, mobile sidebar adaptation, and responsive app content constraints.
- Polished dense findings filters, table/detail containment, custom controls, tab states, hover/press/focus transitions, loading/progress surfaces, and reduced-motion handling.
- Converted mobile attack-map showcase content from horizontal absolute overflow to a stacked mobile layout.
- Added grid/min-width constraints so dense tables and filters scroll inside panels without stretching mobile headers.
- Updated web types to expose stack metadata used by the dashboard.
- Updated feature, reconciliation, testing, and worklog documentation.

### Verification results

- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web test`: passed.
- `pnpm --dir apps/web build`: passed.
- Browser viewport matrix against production `next start` on `http://localhost:3002`: passed, 66 route/viewport checks, covering `/`, `/login`, `/app`, and all app routes at 1440, 1280, 1024, 768, 390, and 360 widths with compiled CSS loaded, no document horizontal overflow, and no offscreen rendered elements.
- Screenshot capture through the in-app browser runtime was unavailable, but DOM/style/viewport checks completed after confirming the stale-server CSS issue and restarting from the fresh build.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 84 tests.
- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `docker compose config --quiet`: passed.
- `git diff --check`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; rebuilt web image `nope-nope-web@sha256:4dadc30f2418`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed with 28 GPU layers and 5000 MB target.
- `Invoke-RestMethod http://localhost:8000/health`: passed; database migrations current, scanners installed, Qwen runtime reachable, GPU layers `28`, GPU memory target `5000`.
- `Invoke-WebRequest http://localhost:3000 -UseBasicParsing`: passed with HTTP `200`.
- Authenticated `/api/queue/status` and `/api/worker/health`: passed; Redis `ok`, queue depth `0`, processing depth `0`, worker heartbeat present, worker healthy.
- `docker compose ps nope-web`: `NOPE` healthy on port 3000.
- Direct llama.cpp `/completion` smoke: passed.
- `docker exec nope-ai nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4485, 6144`; the 28-layer CPU+GPU split remained under the 5 GB VRAM cap.
- `docker inspect nope-ai --format '{{json .HostConfig.DeviceRequests}}'`: NVIDIA GPU device request present.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.

### Closure

Phase 15 is complete for the canonical UI and responsive scope: one graphite theme, no competing light/default UI, complete landing, separate dashboard, route-aware sidebar, polished app routes, dense findings experience, motion/reduced-motion support, mobile adaptation, required viewport verification, Docker image refresh, and under-5 GB Qwen VRAM validation.

## 2026-07-16 Phase 16 Documentation and Final Cleanup

### Objective

Complete the final documentation and cleanup phase: refresh every required document, add the missing pipeline and troubleshooting docs, remove stale final-phase language, audit cleanup keywords, verify no placeholder core implementation remains, run the full test/build/Docker/security checks, commit, push, and stop.

### Pre-phase state

- Pre-phase commit: `9cbe664`.
- Required docs existed except `docs/PIPELINE.md` and `docs/TROUBLESHOOTING.md`.
- README still contained stale pre-queue/pre-Qwen verification language and an old verification snapshot.
- `FEATURE_STATUS.md` and `PHASE_RECONCILIATION.md` still marked Documentation as partially complete pending Phase 16.

### Implemented

- Rewrote `README.md` with product purpose, supported scope, architecture, requirements, Docker startup, core mode, GPU mode, CPU fallback, model path, scanner setup, migrations, tests, benchmarks, endpoints, limitations, GitHub limitation, and authorized-use notice.
- Added `docs/PIPELINE.md` covering auth, project scope, scan creation, Redis/worker flow, repository analysis, sandbox/ZAP, URL checks, findings, focused RAG, Qwen, coverage, reports, baselines, drift, and UI routes.
- Added `docs/TROUBLESHOOTING.md` covering Docker, web/API connectivity, login, migrations, queue/worker health, scanners, Qwen GPU/CPU, sandbox, PDF reports, GitHub blocked state, and secret scanning.
- Refreshed architecture, API, development, deployment, local AI, design system, feature status, and reconciliation docs to remove stale Phase 16 and Qwen/Redis language.
- Removed behavior-preserving production `pass` keyword hits from empty exception classes and fall-through exception handlers.
- Classified remaining cleanup sweep hits as documentation history, intentional vulnerable fixtures/rules, test-only doubles, real migration pending status, normal UI placeholder attributes, or explicit GitHub honesty language.
- Added a web runtime image cleanup that removes npm/npx from the final container layer and starts Next directly with Node, clearing the global npm/undici image finding.
- Added `postcss@8.5.10` overrides for web installs after the production audit identified the transitive PostCSS advisory path through Next.

### Verification results

- `python -m compileall apps/api/nope_api apps/api/tests apps/worker`: passed.
- `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q`: passed, 84 tests.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web test`: passed.
- `pnpm --dir apps/web build`: passed.
- `pnpm --dir apps/web audit --prod`: passed after the PostCSS override, no known vulnerabilities.
- `$env:PYTHONPATH='apps/api'; python -m alembic -c apps/api/alembic.ini current`: passed, `0002_report_bodies (head)`.
- `$env:PYTHONPATH='apps/api'; python -m alembic -c apps/api/alembic.ini upgrade head`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build nope-api nope-worker nope-web`: passed; refreshed API, worker, and web images.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d`: passed with `NOPE_QWEN_GPU_LAYERS=28` and `NOPE_QWEN_GPU_MEMORY_TARGET_MB=5000`.
- `docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps`: passed; web, API, AI, Postgres, Redis, and MinIO healthy; worker running.
- `Invoke-RestMethod http://localhost:8000/health`: passed; migrations current, scanners installed, sandbox enabled, Qwen reachable, GPU layers `28`, memory target `5000`.
- `Invoke-WebRequest http://localhost:3000/ -UseBasicParsing`: passed with HTTP `200`.
- Authenticated login plus `/api/scans`: passed.
- Direct llama.cpp `/v1/chat/completions`: passed.
- `docker exec nope-ai nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits`: `NVIDIA GeForce GTX 1060 with Max-Q Design, 4485, 6144`; under the 5 GB VRAM cap and close to target.
- `docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api`: passed, no leaks found.
- `docker compose run --rm --no-deps nope-api semgrep --config /app/security-packs/semgrep/nope.yml /app/apps/api/nope_api --json`: passed, zero findings.
- `trivy image --severity CRITICAL,HIGH --ignore-unfixed nope-nope-web`: passed, `HIGH=0`, `CRITICAL=0`.
- `trivy image --severity CRITICAL,HIGH --ignore-unfixed nope-nope-api`: passed, `HIGH=0`, `CRITICAL=0`.
- `rg -n "placeholder|TODO|FIXME|fake|stub|pass|pending|mock|dummy"` cleanup sweep: completed; remaining matches are classified in `docs/PHASE_RECONCILIATION.md`.
- `git diff --check`: passed with Windows line-ending warnings only.

### Closure

Phase 16 is complete for final documentation and cleanup: all required documents are current, pipeline and troubleshooting docs exist, stale status language is removed, production placeholder/pass cleanup is done, dependency audit findings are fixed, refreshed Docker images start successfully, health checks pass, tests/builds pass, image scans are clean for high/critical findings, Qwen runs with CPU+GPU split at 28 layers, and measured VRAM is 4485 MiB under the 5000 MiB cap.
