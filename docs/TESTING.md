# NOPE Testing

Phase 13 expands the test contract into core, integration, E2E, security, and optional GPU lanes.

## Core Backend

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests -q
```

Core tests run without Qwen and cover repositories, migrations, scan states, queue serialization, scanner applicability, command construction, parsers, severity normalization, fingerprints, deduplication, suppression expiry, drift, RAG, secret redaction, AI output parsing, PDF reports, sandbox policies, settings validation, and benchmarks.

## Phase 13 Focus

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests/test_phase13_expansion.py -q
```

This file adds explicit unit, integration, E2E, and NOPE-security tests:

- Unit: migrations, scanner command construction, core repository scan with AI disabled.
- Integration: scan ownership, artifact ownership, report ownership.
- E2E: login, project creation, ZIP upload, scan start, progress events, findings filtering, finding detail, evidence tabs, Qwen explanation fallback, report download, baseline, comparison, settings persistence.
- Security: cross-user access, malformed ZIP, private URL blocking, bearer-only CSRF posture, login rate limiting, command construction safety, redaction.

## Phase 14 Pipeline

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests/test_phase14_pipeline.py -q
```

This file proves the full local pipeline: login, project creation, full ZIP upload, queued scan payload, worker execution, stack detection, attack-surface mapping, code graph, scanner selection, URL checks, persisted evidence, Qwen/RAG review contract, reports, baseline, modified second scan, drift persistence, and failure paths.

## Frontend

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test
pnpm --dir apps/web build
```

The current frontend test command is a CI-compatible TypeScript no-emit check. Browser E2E visual polish remains Phase 15.

## Docker

```powershell
docker compose config --quiet
docker compose build nope-api nope-worker nope-web
docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d
docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps
```

## Optional GPU

GPU/Qwen checks are optional for the core suite and should stay separate from the required backend tests:

```powershell
docker compose run --rm --no-deps -e NOPE_AI_PROVIDER=llama.cpp -e NOPE_QWEN_ENDPOINT=http://nope-ai:8080 nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-benchmark-scanner-plus-qwen.json
```
