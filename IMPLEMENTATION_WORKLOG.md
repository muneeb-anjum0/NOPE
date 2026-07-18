# IMPLEMENTATION WORKLOG

## 2026-07-18 Forensic Audit And AI Runtime Fix

Commit pushed before audit: `a46bbc5 Enable base Docker AI runtime`.

Changes made before the audit:

- Base `docker-compose.yml` now starts `nope-ai` without requiring the GPU override profile.
- API and worker default to `NOPE_AI_PROVIDER=llama.cpp` in Docker.
- Base llama.cpp command now defaults to `--n-gpu-layers 28`.
- Base model mount defaults to `D:/Desktop/Model`, matching the local GGUF location.
- Qwen action requests now use no-think routing, prompt caching, and single-pass RAG context reuse.

Verification:

- `python -m pytest apps/api/tests -q`: `94 passed, 2 warnings`.
- `pnpm web:lint`: passed.
- `pnpm web:typecheck`: passed.
- `pnpm web:build`: passed.
- `docker compose up --build -d`: passed.
- API health: Qwen provider `llama.cpp`, GPU layers `28`, runtime reachable.
- `nvidia-smi` inside `nope-ai`: about `4049 / 6144 MiB`.
- AI latency profile after safe optimization: Explain 35.58s, Challenge 45.74s, Fix 37.49s, Test 33.97s uncached; repeated same action 0.0s from cache.
- E2E scan `scan_356656eeadfa4c6a`: completed, 24 findings, Qwen review complete, JSON/MD/SARIF/PDF reports returned HTTP 200.

Known failures after audit:

- `pnpm api:lint` fails on host because `ruff` is not installed.
- Scanner-only and scanner-plus-Qwen benchmarks both fail quality gates.
- E2E scan events endpoint returned zero events.

## 2026-07-18 Stage 1 Benchmark Correctness

Commit target: Stage 1 implementation.

Changes:

- Expanded NOPE deterministic rules for benchmark categories: SQL injection, NoSQL injection, unsafe HTML/XSS, SSRF, path traversal, unsafe upload, missing rate limit, debug exposure, public source maps, unsafe Supabase RLS, public storage, and tracker-before-consent.
- Fixed authorization validation so client-controlled role/tenant signals are promoted as evidence instead of rejected as safe scope.
- Added benchmark negative controls for parameterized SQL, scoped authorization, consent-gated tracker loading, and placeholder secrets.
- Upgraded the expected benchmark manifest to version 2 with severity, confidence, CWE, OWASP, line/range, scanner expectation, Qwen expectation, and dedupe expectation.
- Benchmark output now includes precision, recall, F1, duplicate/supporting evidence count, and a Markdown summary.
- Known false negatives no longer pass the benchmark gate.
- Added `.github/workflows/benchmarks.yml` to run scanner-only in the API scanner image and upload JSON/Markdown benchmark artifacts in CI.

Verification:

- `python -m pytest apps/api/tests -q`: `95 passed, 2 warnings`.
- `pnpm web:lint`: passed.
- `pnpm web:typecheck`: passed.
- `pnpm web:build`: passed.
- `docker compose up --build -d`: passed; web/API/AI/Postgres/Redis/MinIO healthy, worker running.
- `docker compose exec -T nope-api python -m nope_api.benchmarks --mode scanner-only --output /tmp/nope-benchmark-scanner-only-final.json`: passed, precision/recall/F1 `1.000`, `0` FP, `0` FN, duration `37.044s`.
- `docker compose exec -T nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-benchmark-scanner-plus-qwen-final.json`: passed, precision/recall/F1 `1.000`, `0` FP, `0` FN, duration `76.587s`.
- `docker compose exec -T nope-ai nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader,nounits`: `4053, 6144`.

Remaining next-stage failure:

- Durable scan event/progress history remains Stage 2 and is not claimed complete.
