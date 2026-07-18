# NOPE Capability Matrix

Date: 2026-07-18

| Capability | Intended result | Current implementation | Evidence | Status | Completion | Gap severity | Next work |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| Docker app startup | Docker Desktop/plain compose starts full app including AI | Base compose now starts CUDA `nope-ai`; API/worker depend on it | `docker compose up --build -d`, health, inspect command | Verified | 90% | Minor | Document Windows model path requirement |
| ZIP scanning | Upload repo ZIP and scan | Real E2E completed with 24 findings | `scan_356656eeadfa4c6a` | Verified | 85% | Moderate | Better event persistence and larger-repo tests |
| PostgreSQL | Durable projects/scans/findings/reports/settings | Migrations clean; storage layer active | migration status, E2E | Verified | 85% | Minor | More restart-persistence tests |
| Redis/worker | Async queue with durable progress/retry/cancel | Worker completes jobs; Stage 2 persists ordered scan/stage/scanner/retry/cancel/worker/report/Qwen events to Postgres and exposes paginated replay; Stage 3 makes the worker non-root and socketless | Stage 2 tests, Stage 3 tests, E2E, pytest | Verified local Stage 3 | 90% | Minor | Production runner hardening can use rootless Docker or a separate host |
| Scanner orchestration | Broad scanner execution with normalized findings | Main Docker scanners run; Stage 1 benchmark gates pass across all 41 required categories | scanner versions, E2E, final Docker benchmarks | Verified benchmark gate | 86% | Moderate | Event durability and scanner-family expansion in later stages |
| Evidence gate | Promote stronger findings, reduce weak heuristics | Context validation now handles client-controlled auth, policy/config evidence, same-line rule dedupe, and benchmark negative controls | code/tests/final benchmark evidence | Improved | 84% | Moderate | Finding lifecycle completion in Stage 6 |
| Qwen | Local GPU model for review/actions | Live llama.cpp with 28 layers, under 5 GB | health, action smoke, VRAM | Verified local | 78% | Moderate | Durable cache/async UI; speed limited by hardware |
| RAG | Evidence-grounded context | Lexical/graph retrieval with redaction | Qwen evidence payload | Partial | 70% | Moderate | Better source provenance/ranking |
| Findings UX | Filter, paginate, detail, AI actions | Functional routes/build; AI actions work | build, E2E, action smoke | Partial | 78% | Moderate | Browser automation and large findings UX |
| Attack map | Show route/file/data/risk paths | Heuristic graph renders when evidence exists | code/UI/E2E scan has graph | Partial | 70% | Moderate | More parser-backed graph precision |
| Coverage | Explain tested/untested areas | UI/backend records include static, URL, sandbox, and ZAP dynamic state | route/build/E2E plus Stage 4 dynamic tests | Improved | 80% | Moderate | More actionable coverage taxonomy in later stages |
| Assets | Folder-scoped inventory | UI summarizes evidence-connected assets | route/build/source | Partial | 72% | Moderate | Full indexed inventory and search |
| Reports | JSON/MD/SARIF/PDF | All four returned 200 in E2E | E2E report outputs | Verified | 84% | Minor | Async generation/large report tests |
| Drift/baselines | Same-folder comparisons | Implemented and tested | pytest and UI source | Partial | 74% | Moderate | More transparent baseline UX |
| Sandbox | Safe dynamic testing | Internal `nope-runner` owns Docker access; worker is socketless; sandbox jobs enforce image/command/network/mount/env/resource limits; Stage 4 adds supported Node/Python app starts and private-network ZAP baseline | Stage 3 hostile matrix, Stage 4 dynamic suite, live ZAP smoke | Verified local Stage 4 | 88% | Minor | Broader browser-authenticated dynamic depth in later stages |
| Settings | Persist AI/scanner/project settings | Implemented; encrypted test secrets | source/tests | Partial | 78% | Moderate | Verify all settings consumed at runtime |
| GitHub | Private repo/PR workflow | Blocked adapter/contracts only | routes/docs/source | Superficial/blocked | 35% local, 0% activated | Major | OAuth/App credentials and implementation |
| Documentation | Accurate setup/status | Extensive but overclaims | audit comparison | Partial | 58% | Moderate | Update stale completion claims |

## Stage 1 benchmark evidence

Final Docker benchmark run on 2026-07-18:

| Mode | Status | Precision | Recall | F1 | False positives | False negatives | Known false negatives | Duration |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| scanner-only | passed | 1.000 | 1.000 | 1.000 | 0 | 0 | 0 | 37.416s |
| scanner-plus-Qwen | passed | 1.000 | 1.000 | 1.000 | 0 | 0 | 0 | 99.575s |

## Scanner matrix

| Scanner | Installed in Docker | Version verified | Execution verified | Parser/normalization | Raw artifact | Failure handling | Completion |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| Semgrep | Yes | 1.170.0 | Yes | Yes | Captured in scan model | Yes | 80% |
| Gitleaks | Yes | 8.28.0 | Yes | Yes | Captured | Yes | 78% |
| OSV-Scanner | Yes | 2.2.3 | Yes | Yes | Captured | Yes | 80% |
| Trivy | Yes | 0.72.0 | Yes | Yes | Captured | Yes | 80% |
| Checkov | Yes | 3.3.8 | Yes | Yes | Captured | Yes | 75% |
| Bandit | Yes | 1.9.4 | Yes | Yes | Captured | Yes | 78% |
| Hadolint | Yes | 2.14.0 | Yes | Yes | Captured | Yes | 78% |
| ZAP | Image/config exists | Version captured from runtime output | Private internal-network baseline verified for supported manifests | Alerts parsed into NOPE findings | Raw JSON/config artifact captured | Skipped/partial/failed/readiness/timeout handled | 85% |
| npm audit | Yes | Docker rebuild required | Controlled command/parser tests | Yes | Captured by scanner-run artifact path | Yes | 100% local |
| pnpm audit | Yes | Docker rebuild required | Controlled command/parser tests | Yes | Captured by scanner-run artifact path | Yes | 100% local |
| yarn audit | Yes | Docker rebuild required | Controlled command/parser tests | Yes | Captured by scanner-run artifact path | Yes | 100% local |
| pip-audit | Yes | Docker rebuild required | Controlled command/parser tests | Yes | Captured by scanner-run artifact path | Yes | 100% local |
| dotnet package audit | Plugin present; SDK not bundled | Unavailable unless SDK installed | Controlled command/parser tests | Yes | Captured when tool runs | Yes | 100% plugin / external tool |
| cargo audit | Plugin present; cargo-audit not bundled | Unavailable unless cargo-audit installed | Controlled command/parser tests | Yes | Captured when tool runs | Yes | 100% plugin / external tool |
| govulncheck | Plugin present; govulncheck not bundled | Unavailable unless installed | Controlled command/parser tests | Yes | Captured when tool runs | Yes | 100% plugin / external tool |
| composer audit | Plugin present; Composer not bundled | Unavailable unless Composer installed | Controlled command/parser tests | Yes | Captured when tool runs | Yes | 100% plugin / external tool |
| bundler-audit | Plugin present; bundler-audit not bundled | Unavailable unless installed | Controlled command/parser tests | Yes | Captured when tool runs | Yes | 100% plugin / external tool |
