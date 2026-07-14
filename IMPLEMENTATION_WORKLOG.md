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
