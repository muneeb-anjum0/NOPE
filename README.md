# NOPE

Your app works. That does not mean it is secure.

NOPE is a local-first, rules-first, AI-assisted application security orchestration platform. It accepts authorized repository ZIPs and URLs, runs deterministic scanner evidence first, connects that evidence through the pipeline, optionally asks local Qwen for focused reasoning, and reports what is verified, partial, failed, or untested.

NOPE does not claim an app is fully secure, guaranteed safe, unhackable, or formally compliant.

## Supported Scope

NOPE currently supports:

- Local login with Postgres-backed users and sessions.
- Repository ZIP ingestion with archive safety checks.
- Authorized URL checks with private-network blocking by default.
- Full scans that combine repository and URL evidence.
- Redis-backed queueing and worker execution.
- Stack detection, attack-surface mapping, and lightweight code graph creation.
- Real scanner execution for Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, and Bandit in the API image.
- Optional sandbox workflows and internal ZAP baseline scans through `.nope/sandbox.json`.
- Canonical findings, deduplication, lifecycle history, baselines, drift, and coverage.
- Reports in JSON, Markdown, SARIF, and PDF.
- Optional local Qwen through llama.cpp Docker, with CPU and GPU profiles.
- Local GitHub contract settings, with private repository access honestly blocked until real credentials are supplied and verified.

Out of scope for this local build: email, SMTP, payments, subscriptions, production cloud deployment, and formal compliance certification.

## Architecture

Services:

- `NOPE` / `nope-web`: Next.js landing page and dashboard.
- `nope-api`: FastAPI orchestration API.
- `nope-worker`: Redis worker for queued scans.
- `nope-postgres`: local auth, projects, scans, findings, settings, reports, baselines, and drift.
- `nope-redis`: queue, cancellation flags, processing tracking, and worker heartbeat.
- `nope-minio`: raw scanner artifacts and PDF report artifacts.
- `nope-ai`: optional llama.cpp server for local Qwen inference.

Main flow:

```text
Login
  -> create project
  -> upload ZIP and/or authorize URL
  -> persist queued scan
  -> enqueue Redis job
  -> worker executes stack, graph, rules, scanners, sandbox, URL checks
  -> normalize and deduplicate findings
  -> focused RAG and optional Qwen review
  -> coverage, score, verdict, reports, baseline, drift
  -> dashboard and API exports
```

See `docs/ARCHITECTURE.md` and `docs/PIPELINE.md`.

## Requirements

- Docker Desktop with Docker Compose.
- Node.js 22+ or 24+ for local web development.
- pnpm 10+ for local web development.
- Python 3.11+ for local API tests.
- Optional NVIDIA container support for GPU Qwen.
- Optional local GGUF model file at `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`.

Do not commit the GGUF model, `.env`, scanner artifacts, or local benchmark output.

## Endpoints

- Web UI: `http://localhost:3000`
- Login: `http://localhost:3000/login`
- Dashboard: `http://localhost:3000/app/projects/local`
- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- MinIO UI: `http://localhost:9001`
- llama.cpp debug endpoint: `http://localhost:8081` when an AI profile is enabled

Except for `GET /health` and `POST /api/auth/login`, API routes require `Authorization: Bearer <token>`. The dashboard forwards the local HttpOnly session cookie server-side.

## Docker Startup

Core mode without AI:

```powershell
docker compose up --build -d
```

GPU Qwen mode:

```powershell
$env:NOPE_MODEL_HOST_DIR='D:/Desktop/Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'
$env:NOPE_QWEN_GPU_LAYERS='28'
$env:NOPE_QWEN_GPU_MEMORY_TARGET_MB='5000'
docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up --build -d
```

CPU fallback:

```powershell
$env:NOPE_MODEL_HOST_DIR='D:/Desktop/Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'
docker compose --profile ai-cpu -f docker-compose.yml -f docker-compose.ai-cpu.yml up --build -d
```

Shutdown:

```powershell
docker compose down
```

Use `docker compose down -v` only when you intentionally want to remove local Postgres, Redis, MinIO, and workspace volumes.

## Model Path

Verified local model:

```text
D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf
```

Container path:

```text
/models/Qwen3-8B-Q4_K_M.gguf
```

The verified GPU setting is 28 layers with a 5000 MiB target. On the local GTX 1060 Max-Q, the CUDA container measured 4485 MiB used out of 6144 MiB during Phase 15/16 verification. Thirty layers previously failed to fit, so 28 is the stable cap-safe setting.

## Scanner Setup

The Docker API image bundles:

- Semgrep
- Gitleaks
- OSV-Scanner
- Trivy
- Checkov
- Hadolint
- Bandit

OWASP ZAP baseline runs only through the sandbox dynamic path when a repository declares a safe internal target. Static repository scans mark ZAP not applicable instead of fabricating results.

Local host scanner CLIs are optional for development. Docker is the verified scanner runtime.

## Migrations

The API applies SQL migrations at startup through `nope_api.db.run_migrations()`. Alembic wrappers are also available for explicit checks:

```powershell
alembic -c apps/api/alembic.ini upgrade head
alembic -c apps/api/alembic.ini current
```

Use downgrade checks only against disposable data.

See `docs/DATABASE.md`.

## Tests

Backend:

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests -q
python -m compileall apps/api/nope_api apps/api/tests apps/worker
```

Frontend:

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test
pnpm --dir apps/web build
```

Docker and security:

```powershell
docker compose config --quiet
docker compose build nope-api nope-worker nope-web
docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api
```

## Benchmarks

Scanner-only:

```powershell
$env:PYTHONPATH='apps/api'
python -m nope_api.benchmarks --mode scanner-only --output .nope-benchmark-results/scanner-only.json
```

Scanner plus Qwen:

```powershell
$env:PYTHONPATH='apps/api'
python -m nope_api.benchmarks --mode scanner-plus-qwen --output .nope-benchmark-results/scanner-plus-qwen.json
```

See `docs/BENCHMARKS.md`.

## API Highlights

- `GET /health`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/scans/url`
- `POST /api/scans/repository`
- `POST /api/scans/full`
- `POST /api/scans/{scan_id}/cancel`
- `POST /api/scans/{scan_id}/retry`
- `GET /api/scans/{scan_id}/events`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/findings/{finding_id}`
- `GET /api/scans/{scan_id}/report.{format}`
- `POST /api/scans/{scan_id}/baseline`
- `GET /api/scans/{scan_id}/compare`
- `GET /api/queue/status`
- `GET /api/worker/health`
- `GET /api/scanners/capabilities`
- `GET /api/settings/system`
- `GET /api/github/status`

See `docs/API_REFERENCE.md`.

## Limitations

- Private GitHub repository access is blocked until real GitHub App/OAuth credentials are supplied and verified. NOPE does not fake repositories.
- URL-only scans are non-destructive and do not prove runtime security.
- Sandbox dynamic testing requires an explicit `.nope/sandbox.json` manifest.
- Qwen is optional and cannot override deterministic scanner evidence.
- Benchmarks include known false negatives so scanner gaps stay visible.
- This repository is configured for local Docker, not production cloud deployment.

## Authorized-Use Notice

Only scan repositories and URLs that you own or are explicitly authorized to test. NOPE enforces local scope checks, but authorization remains the operator's responsibility.

## Documentation Map

- `docs/ARCHITECTURE.md`
- `docs/SECURITY_MODEL.md`
- `docs/DEVELOPMENT.md`
- `docs/DEPLOYMENT.md`
- `docs/API_REFERENCE.md`
- `docs/LOCAL_AI.md`
- `docs/DATABASE.md`
- `docs/PIPELINE.md`
- `docs/SCANNERS.md`
- `docs/SANDBOX.md`
- `docs/BENCHMARKS.md`
- `docs/DESIGN_SYSTEM.md`
- `docs/TROUBLESHOOTING.md`
- `docs/FEATURE_STATUS.md`
- `docs/PHASE_RECONCILIATION.md`
- `docs/IMPLEMENTATION_WORKLOG.md`

## README Maintenance

Keep this README current whenever ports, services, run commands, scanner support, AI settings, verification results, or limitations change. Do not mark a capability complete unless it is implemented and verified.
