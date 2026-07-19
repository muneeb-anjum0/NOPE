# NOPE Testing

Use these commands from the repository root unless noted.

## Backend

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests -q
python -m compileall apps/api/nope_api apps/api/tests apps/worker
```

Focused lanes:

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests/test_phase14_pipeline.py -q
python -m pytest apps/api/tests/test_stage2_scan_events.py -q
python -m pytest apps/api/tests/test_stage3_security_hardening.py apps/api/tests/test_stage4_dynamic_zap.py -q
python -m pytest apps/api/tests/test_stage6_findings_lifecycle.py apps/api/tests/test_stage7_qwen_rag.py -q
python -m pytest apps/api/tests/test_stage9_github_integration.py apps/api/tests/test_persistence.py -q
python -m pytest apps/api/tests/test_stage11_self_security.py apps/api/tests/test_api_auth.py apps/api/tests/test_security.py -q
```

Host Ruff is optional. The canonical Docker image contains the scanner/runtime dependencies used by the product; do not treat missing host Ruff as a product failure.

## Frontend

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web build
```

The root package aliases are:

```powershell
pnpm web:typecheck
pnpm web:build
pnpm web:e2e
pnpm web:e2e:update
```

## Browser E2E, Accessibility, And Visual Regression

```powershell
pnpm --dir apps/web exec playwright install chromium
pnpm web:e2e
```

The Playwright suite runs Next.js in deterministic fixture mode and covers:

- landing, login, logout, session persistence
- project creation, ZIP upload, scan start/progress/completion/partial/failure/cancel/retry/delete
- findings filters, load-more behavior, row selection, detail tabs, lifecycle states, and Qwen actions
- attack map, coverage, assets, reports, baselines, drift, settings, error states, empty states, and mobile navigation
- axe checks, keyboard focus, dialog focus trapping, Escape behavior, labels, reduced motion, and named icon buttons
- visual snapshots at `1440`, `1280`, `1024`, `768`, `390`, and `360` widths

Update snapshots only when a deliberate UI change is being accepted:

```powershell
pnpm web:e2e:update
```

## Benchmarks

Scanner-only:

```powershell
docker compose run --rm --no-deps nope-api python -m nope_api.benchmarks --mode scanner-only --output /tmp/nope-benchmark-scanner-only.json
```

Scanner plus Qwen:

```powershell
docker compose run --rm --no-deps -e NOPE_AI_PROVIDER=llama.cpp -e NOPE_QWEN_ENDPOINT=http://nope-ai:8080 nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-benchmark-scanner-plus-qwen.json
```

The Qwen benchmark requires the local model runtime to be up and reachable.

## Docker And Migrations

```powershell
docker compose config --quiet
docker compose build nope-api nope-worker nope-web nope-runner
docker compose up -d
docker compose ps

$env:PYTHONPATH='apps/api'
python -m alembic -c apps/api/alembic.ini upgrade head
python -m alembic -c apps/api/alembic.ini current
```

## Security, Dependency, And Container Checks

```powershell
pnpm --dir apps/web audit --audit-level high
docker compose run --rm --no-deps --entrypoint python nope-api -m pip check
docker compose run --rm --no-deps -e TMPDIR=/app/.nope-workspaces --entrypoint pip-audit nope-api -r /app/apps/api/requirements.txt --progress-spinner off
docker compose run --rm --no-deps -e TRIVY_CACHE_DIR=/app/.nope-workspaces/trivy-cache --entrypoint trivy nope-api fs --cache-dir /app/.nope-workspaces/trivy-cache --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 --skip-dirs /app/.nope-workspaces --skip-dirs /app/apps/api/tests/fixtures --skip-dirs /app/benchmarks /app
```

`pip-audit` currently reports the documented Semgrep/OpenTelemetry protobuf scanner-chain residual in `docs/SECURITY_MODEL.md`. Production-code Trivy scanning excludes intentionally vulnerable security fixtures.

## Clean-Room Verification

Stage 12 clean-room verification may remove local Compose volumes:

```powershell
docker compose down -v
docker compose up --build -d
```

Use this only when a local data reset is acceptable.
