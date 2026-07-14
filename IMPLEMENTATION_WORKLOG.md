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
