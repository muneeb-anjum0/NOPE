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
