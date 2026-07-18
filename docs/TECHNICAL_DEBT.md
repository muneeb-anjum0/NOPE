# NOPE Technical Debt

Date: 2026-07-18

## Critical

- Benchmark scanner quality fails in both scanner-only and scanner-plus-Qwen modes.
- Worker container runs as root and mounts Docker socket to launch sandbox containers.
- GitHub private repository access is not implemented beyond blocked contracts.

## High

- Event/progress persistence is incomplete; E2E scan completed with zero returned events.
- AI action cache is process-memory plus browser localStorage; server restart loses API cache.
- Qwen first-run latency is 34-46 seconds per structured action on the current GPU/model.
- Host `pnpm api:lint` fails because `ruff` is not installed.
- Dynamic/ZAP testing is skipped for ordinary repo scans.

## Medium

- Attack map/code graph remains heuristic and can miss true data/control flow.
- Documentation overclaims phase completeness against current benchmark results.
- Frontend lacks formal Playwright/axe regression coverage.
- Scanner family coverage is uneven; several requested ecosystem audit tools are not first-class plugins.
- Settings exist, but not every setting has proven runtime consumption in this audit.

## Low

- FastAPI `on_event` deprecation warning.
- pytest-asyncio default fixture loop-scope deprecation warning.
- Some report generation is synchronous and may feel slow on large scans.
