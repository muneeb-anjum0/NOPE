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

The current frontend test command is a CI-compatible TypeScript no-emit check.

## Stage 8 Browser E2E, Accessibility, and Visual Regression

Stage 8 adds a deterministic Playwright lane for the web app:

```powershell
pnpm --dir apps/web exec playwright install chromium
pnpm web:e2e
```

The suite starts Next.js on port `3100` with `NOPE_E2E_FIXTURE=1`. Fixture mode keeps browser tests independent of mutable local scan data while still exercising real Next routes, forms, cookies, redirects, API proxies, client hydration, dialogs, scan event polling, and Qwen action UI states.

Covered widths:

- `1440`
- `1280`
- `1024`
- `768`
- `390`
- `360`

Covered browser flows:

- Landing, login, logout, and session persistence.
- Project folder creation, folder navigation, ZIP upload, scan start, progress UI, cancellation, retry, deletion, partial, failed, and completed scan states.
- Findings filters, DOM-only load more, row selection, expandable detail panel, evidence/code/code-flow/fix/tests/history tabs, lifecycle states, empty states, and Qwen Explain/Challenge/Fix/Test/Patch Review actions.
- Attack map, coverage, assets, reports, baselines, drift, settings, mobile sidebar navigation, and mobile collapse behavior.

Accessibility coverage:

- Axe checks on `/`, `/login`, overview, scan folders, scan folder detail, findings, attack map, coverage, assets, reports, and settings.
- Keyboard focus, focus indicators, dialog focus trapping, Escape close behavior, labels, named icon buttons, reduced motion behavior, and focusable scroll regions.

Visual regression:

```powershell
pnpm web:e2e:update
pnpm web:e2e
```

Snapshots are deterministic by freezing animations and masking volatile time fields. The suite captures app-shell screenshots at every required width and dense route snapshots once at `1280`.

## Phase 15 UI Viewports

Phase 15 uses the in-app browser runtime against a production `next start` build and verifies these routes at `1440`, `1280`, `1024`, `768`, `390`, and `360` pixel widths:

- `/`
- `/login`
- `/app`
- `/app/projects/local`
- `/app/projects/local/findings`
- `/app/projects/local/attack-map`
- `/app/projects/local/coverage`
- `/app/projects/local/scans`
- `/app/projects/local/assets`
- `/app/projects/local/reports`
- `/app/projects/local/settings`

The check asserts the compiled graphite stylesheet is loaded, the active app route is present, document-level horizontal overflow is absent, and visible rendered elements are not offscreen outside intentional scroll containers.

## Docker

```powershell
docker compose config --quiet
docker compose build nope-api nope-worker nope-web
docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d
docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml ps
```

## Stage 11 Self-Security

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests/test_stage11_self_security.py apps/api/tests/test_api_auth.py apps/api/tests/test_security.py -q
python -m pytest apps/api/tests -q
pnpm web:typecheck
pnpm --dir apps/web lint
pnpm web:build
pnpm --dir apps/web audit --audit-level high
docker compose config --quiet
docker compose build nope-api
docker compose run --rm --no-deps --entrypoint python nope-api -m pip check
docker compose run --rm --no-deps -e TMPDIR=/app/.nope-workspaces --entrypoint pip-audit nope-api -r /app/apps/api/requirements.txt --progress-spinner off
docker compose run --rm --no-deps -e TRIVY_CACHE_DIR=/app/.nope-workspaces/trivy-cache --entrypoint trivy nope-api fs --cache-dir /app/.nope-workspaces/trivy-cache --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 --skip-dirs /app/.nope-workspaces --skip-dirs /app/apps/api/tests/fixtures --skip-dirs /app/benchmarks /app
```

`pip-audit` currently reports the documented Semgrep/OpenTelemetry protobuf scanner-chain residual in `docs/SECURITY_MODEL.md`; production-code Trivy scanning excludes intentionally vulnerable security fixtures.

## Optional GPU

GPU/Qwen checks are optional for the core suite and should stay separate from the required backend tests:

```powershell
docker compose run --rm --no-deps -e NOPE_AI_PROVIDER=llama.cpp -e NOPE_QWEN_ENDPOINT=http://nope-ai:8080 nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-benchmark-scanner-plus-qwen.json
```
