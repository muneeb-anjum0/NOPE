# NOPE Final Clean-Room Audit

Date: 2026-07-19
Stage 12 pre-stage commit: `6267b3c6b05c0671d2d311876b3b25f3e4885dd1`

This document is the Stage 12 evidence ledger. It is updated only with commands that were actually run during the final clean-room pass.

## Final Verification Checklist

| Step | Status | Evidence |
| --- | --- | --- |
| Record pre-stage commit and clean worktree | PASS | `git rev-parse HEAD` -> `6267b3c6b05c0671d2d311876b3b25f3e4885dd1`; initial `git status --short` clean. |
| Inspect docs and audit files | PASS | README, master plan, status, security, testing, architecture, pipeline, deployment, and historical audits reviewed. |
| Remove stale completion claims | PASS | Root status/worklog, current audit, capability matrix, phase audit, technical debt, testing docs, and master plan updated to reflect approved Stages 1-11 and active Stage 12. |
| Cleanup keyword sweep | PASS | Sweep classified remaining hits as intentional scanner rule text, vulnerable benchmark fixtures, test doubles, UI placeholder attributes, documented blocked/unsupported states, historical worklog entries, or legitimate runtime states. No production placeholder/stub/fake adapter requiring removal was found. |
| Docker clean-room rebuild | PASS | `docker compose down -v`; `docker compose up --build -d`; all canonical services rebuilt and started on the refreshed stack. |
| Fresh migrations | PASS | Authenticated `/api/health/details` showed applied migrations `0001_initial` through `0005_ai_actions`, with no pending or unexpected migrations. |
| Service health | PASS | `docker compose ps` showed web/API/AI/Postgres/Redis/MinIO/runner healthy and worker running; public `/health` returned `status: ok`. |
| Static scan | PASS | Docker scanner-only benchmark passed with 41/41 expected true positives and 0 false positives/false negatives. |
| AI-assisted scan/action | PASS | Docker scanner-plus-Qwen benchmark passed against local `llama.cpp`; authenticated health showed AI provider `llama.cpp`, model `qwen3-8b-q4-k-m`, 28 GPU layers, 5000 MB target. |
| Dynamic/ZAP scan | PASS | Full backend suite includes Stage 4 dynamic/ZAP supported Node/Python fixture, URL authorization, failure-state, teardown, artifact, coverage, and parser tests. |
| Durable events | PASS | Full backend suite includes Stage 2 event ordering, pagination, retry, cancellation, heartbeat/stuck-job, restart reconstruction, and authorization tests. |
| Findings/dedupe/lifecycle | PASS | Full backend suite includes Stage 6 canonical schema, stable fingerprints, duplicate merge, correlation, lifecycle, suppression expiry, recurrence, concurrency, and unauthorized update tests. |
| Reports | PASS | Full backend suite includes JSON, Markdown, SARIF, PDF, artifact access, durable retry/failure, large report, redaction, and retention tests. |
| Baseline/drift | PASS | Full backend suite includes latest-vs-previous, latest-vs-baseline, arbitrary comparison, same-project guard, stable fingerprint, and expanded drift category tests. |
| Cancellation/retry/restart/recovery | PASS | Full backend suite includes durable cancellation/retry and API/worker/Redis restart reconstruction paths; Stage 12 also fixed concurrent fresh-start migration safety. |
| Cross-user denial | PASS | Full backend suite includes cross-user project/scan/finding/report/artifact/GitHub denial and self-security tests. |
| Benchmarks | PASS | Scanner-only and scanner-plus-Qwen benchmarks both exited 0 with `status: passed`. |
| Backend tests | PASS | `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q` -> `201 passed, 2 warnings in 238.76s`. |
| Frontend lint/type/build/tests | PASS | `pnpm --dir apps/web typecheck`, `pnpm --dir apps/web lint`, `pnpm --dir apps/web build`, and `pnpm --dir apps/web audit --audit-level high` passed. |
| Browser E2E/a11y/visual | PASS | Stage 12 reran `pnpm web:e2e` before final code-only fixes: `109 passed, 35 skipped`; skipped dense screenshots are classified below and do not block. |
| Dependency/container scans | PASS WITH DOCUMENTED RESIDUAL | `pip check` clean; Trivy production requirements scan found 0 vulnerabilities; web audit found 0 known high vulnerabilities; `pip-audit` reports one documented scanner-chain residual: `protobuf 4.25.9` / `PYSEC-2026-1805`. |
| Documentation commands | PASS | README, testing, operations, GitHub, status, audit, capability, debt, and master-plan docs updated to match actual local behavior and external blocked states. |
| GitHub state | EXTERNALLY BLOCKED | Authenticated `/api/github/status` returned `blocked_missing_credentials` with all credential fields false; local protocol tests cover the integration contract. |
| Commit and push | PASS | Stage 12 cleanup commit `72a209fc1963962eb3262ed5b88b0409ae3030a3` was pushed to `origin/main`; this final adversarial audit section records the post-commit verification pass and will be committed separately. |

## Command Results

Important Stage 12 findings fixed before final verification:

- Fresh clean-room startup exposed a migration race when API and worker booted against an empty Postgres volume. The migration runner now uses a transaction-scoped Postgres advisory lock, with a regression test proving concurrent startup safety.
- Scanner-only benchmark exposed that disabled sandbox mode could still contact the remote runner. Sandbox-disabled scans now return a local skipped result without runner traffic, with a regression test.
- Scanner-only benchmark exposed Trivy cache extraction pressure on hardened `/tmp`. Compose now gives scanner containers a durable Trivy cache directory and a larger API tmpfs.

Commands and results:

| Command | Result |
| --- | --- |
| `git diff --check` | PASS; line-ending warnings only. |
| `docker compose config --quiet` | PASS. |
| `docker compose down -v`; `docker compose up --build -d` | PASS; clean-room stack rebuilt and refreshed. |
| `docker compose ps` | PASS; web/API/AI/Postgres/Redis/MinIO/runner healthy, worker running. |
| `Invoke-RestMethod http://localhost:8000/health` | PASS; public health returned `status: ok`. |
| Authenticated `/api/health/details` | PASS; DB migrations current, scanners enumerated, Qwen reachable, sandbox limits reported. |
| Authenticated `/api/github/status` | PASS; `blocked_missing_credentials`, no external activation claimed. |
| `docker exec nope-ai nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits` | PASS; `NVIDIA GeForce GTX 1060 with Max-Q Design, 4041, 6144`, below the 5 GB VRAM ceiling. |
| `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q` | PASS; `201 passed, 2 warnings in 238.76s`. |
| `python -m compileall apps/api/nope_api apps/api/tests apps/worker` | PASS. |
| `pnpm --dir apps/web typecheck` | PASS. |
| `pnpm --dir apps/web lint` | PASS. |
| `pnpm --dir apps/web build` | PASS. |
| `pnpm --dir apps/web audit --audit-level high` | PASS; no known vulnerabilities found. |
| `pnpm web:e2e` | PASS; `109 passed, 35 skipped`; skip classification below. |
| `docker compose run --rm --no-deps nope-api python -m nope_api.benchmarks --mode scanner-only --output /tmp/nope-benchmark-scanner-only-stage12.json` | PASS; `status: passed`, 41 expected findings, precision/recall/F1 `1.0`, no FP/FN. |
| `docker compose run --rm --no-deps -e NOPE_AI_PROVIDER=llama.cpp -e NOPE_QWEN_ENDPOINT=http://nope-ai:8080 nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-benchmark-scanner-plus-qwen-stage12.json` | PASS; `status: passed`, 41 expected findings, precision/recall/F1 `1.0`, no FP/FN. |
| `docker compose run --rm --no-deps --entrypoint python nope-api -m pip check` | PASS; no broken requirements. |
| `docker compose run --rm --no-deps --entrypoint trivy nope-api fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --skip-dirs /app/.nope-workspaces --skip-dirs /tmp /app/apps/api/requirements.txt` | PASS; 0 vulnerabilities in `requirements.txt`. |
| `docker compose run --rm --no-deps -e TMPDIR=/app/.nope-workspaces --entrypoint pip-audit nope-api -r /app/apps/api/requirements.txt --progress-spinner off` | RESIDUAL; one documented advisory: `protobuf 4.25.9` / `PYSEC-2026-1805`, fixed in protobuf 5.29.6 or 6.33.5. |

Final completion percentages:

| Scope | Percentage | Notes |
| --- | ---: | --- |
| Local product completion for Stages 1-12 | 100% locally achievable and verified | All local code, Docker, database, scanner, worker, sandbox, Qwen, reporting, browser, accessibility, visual, benchmark, and security-regression checks listed above passed, with the documented dependency residual below. |
| External GitHub activation | Blocked | No real GitHub credentials are configured. Local fake-server/protocol tests pass; production GitHub access must be activated with real credentials. |
| Production SaaS readiness | Not claimed | The repo is ready as a local/self-hosted security product; multi-tenant SaaS operations still require production infrastructure, secrets management, observability, backups, abuse monitoring, incident process, and credential activation outside this repo. |

Documented residuals:

- `pip-audit` reports `protobuf 4.25.9` / `PYSEC-2026-1805`. This is a scanner/runtime dependency-chain residual; Trivy did not report a high/critical issue for the pinned requirements file in the same final pass. It remains documented rather than hidden.
- Real GitHub private repository access remains externally blocked until credentials are supplied.
- Production SaaS readiness is intentionally not claimed by this local completion program.

## Cleanup Sweep Classification

Command:

```powershell
rg -n -i "TODO|FIXME|placeholder|stub|mock|fake|demo-only|temporary|in-memory|hardcoded|NotImplemented|NotImplementedError|\bpass\b|skipped|xfail|disabled|no-op|unsupported|later|pending" README.md FEATURE_STATUS.md IMPLEMENTATION_WORKLOG.md docs apps .github docker packages security-packs benchmarks --glob '!**/node_modules/**' --glob '!**/.next/**' --glob '!**/.pytest_cache/**' --glob '!**/playwright-report/**' --glob '!**/test-results/**' --glob '!**/*.png' --glob '!**/*.jpg' --glob '!**/*.jpeg' --glob '!**/*.gif'
```

Result: PASS with classified matches.

| Match family | Classification |
| --- | --- |
| `hardcoded`, `disabled`, `skipAuth`, `placeholder` in `security-packs` and `benchmarks` | Intentional vulnerable rules, fixture manifests, and safe negative controls. |
| `Fake*`, monkeypatch helpers, and `pass` in `apps/api/tests` | Test-only doubles used to verify failure/security paths. |
| `placeholder` in web inputs | User-facing form ghost text, not fake behavior. |
| `pending`, `skipped`, `unsupported`, `disabled` in runtime code | Legitimate scan/event/coverage states that must be reported honestly. |
| `fake` in GitHub docs/settings | Explicit statement that production paths do not fake repository access. |
| Historical `docs/IMPLEMENTATION_WORKLOG.md` entries | Preserved dated history; file now has a header warning that old entries are not current status. |

Skipped test classification:

| File | Test | Reason | Acceptable | Blocks Stage 12 |
| --- | --- | --- | --- | --- |
| `apps/web/tests/e2e/visual.spec.ts` | Dense route snapshots for non-`chromium-1280` projects | Dense route screenshots are intentionally captured once at desktop width while shell snapshots cover all required widths. | Yes | No |

---

# Adversarial Final Clean-Room Completion Audit

Date: 2026-07-19T16:34:04.9173287+05:00
Audit starting commit: `72a209fc1963962eb3262ed5b88b0409ae3030a3`
Branch: `main`
Remote: `https://github.com/muneeb-anjum0/NOPE.git`

This section treats all prior completion claims as untrusted and records the independent final audit performed after Stage 12 was already committed.

## Environment Snapshot

| Item | Evidence |
| --- | --- |
| Host OS | Microsoft Windows 11 Home `10.0.26200`, x64 |
| Docker | Docker `29.6.1`, Compose `v5.2.0` |
| Node / pnpm / Python | Node `v24.16.0`; pnpm `11.5.0`; Python `3.11.9` |
| Playwright | `1.61.1` |
| GPU | NVIDIA GeForce GTX 1060 with Max-Q Design, driver `582.28`, `6144 MB` total |
| Model | `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`, mounted as `/models/Qwen3-8B-Q4_K_M.gguf` |
| llama.cpp | `llama-server` version `10015 (12127defd)` |
| Measured VRAM | `4041 MB / 6144 MB` from inside `nope-ai`, below the intended 5 GB ceiling |
| Scanner versions observed | Semgrep `1.121.0`; Gitleaks `8.28.0`; OSV-Scanner `2.2.3`; Trivy `0.72.0`; Checkov `3.2.531`; Hadolint `2.14.0`; Bandit `1.9.4`; npm `9.2.0`; pnpm `10.26.0`; yarn `1.22.22`; pip-audit `2.9.0` |

## Clean-Room Startup

PASS.

Commands actually run:

```powershell
docker compose down -v --remove-orphans
$env:NOPE_MODEL_HOST_DIR='D:\Desktop\Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'
$env:NOPE_QWEN_GPU_LAYERS='28'
$env:NOPE_QWEN_GPU_MEMORY_TARGET_MB='5000'
docker compose up --build -d
```

Result:

- Fresh volumes were removed and recreated.
- Images built successfully.
- Web build succeeded with one known autoprefixer warning: `start value has mixed support, consider using flex-start instead`.
- `nope-ai` loaded the GGUF model and became healthy.
- API, web, runner, Postgres, Redis, MinIO, and Qwen became healthy; worker was running.
- `/health` returned `status: ok`.
- `/login` returned HTTP `200`.
- Authenticated `/api/health/details` showed migrations `0001_initial` through `0005_ai_actions` applied, with no pending or unexpected migrations.
- Authenticated `/api/github/status` returned `blocked_missing_credentials`.

Container boundary evidence:

| Container | User | Privileged | Cap drop | Root FS | Docker socket |
| --- | --- | --- | --- | --- | --- |
| `nope-api` | `nope` | false | `ALL` | read-only | no |
| `nope-worker` | `nope` | false | `ALL` | read-only | no |
| `NOPE` web | `nope` | false | `ALL` | read-only | no |
| `nope-runner` | `root` | false | `ALL` | read-only | yes, intentionally narrow runner boundary |

Documented local development ports exposed:

- Web: `3000`
- API: `8000`
- MinIO: `9000`, `9001`
- Postgres: `5432`
- Redis: `6379`
- llama.cpp host debug: `127.0.0.1:8081`
- Runner and worker ports are internal only.

CPU and GPU Compose configurations were checked with `docker compose ... config --quiet`; GPU runtime was fully started and measured. CPU-mode config parses, but the final runtime pass used the user-approved GPU setting because that is the intended local AI configuration.

## Test Matrix

| Suite | Command | Result |
| --- | --- | --- |
| Backend unit/integration/security/scanner/recovery/Qwen/RAG/report/drift/GitHub tests | `$env:PYTHONPATH='apps/api'; python -m pytest apps/api/tests -q` | PASS: `201 passed, 2 warnings in 250.22s` |
| Python compile | `python -m compileall apps/api/nope_api apps/api/tests apps/worker` | PASS |
| Frontend typecheck | `pnpm --dir apps/web typecheck` | PASS |
| Frontend lint | `pnpm --dir apps/web lint` | PASS |
| Frontend build | `pnpm --dir apps/web build` | PASS |
| Frontend dependency audit | `pnpm --dir apps/web audit --audit-level high` | PASS: no known vulnerabilities |
| Browser E2E/accessibility/visual | `pnpm web:e2e` | PASS: `109 passed, 35 skipped in 18.4m` |
| Compose validation | `docker compose config --quiet` plus CPU/GPU overlay config | PASS |
| Migration command | `$env:PYTHONPATH='apps/api'; python -m alembic -c apps/api/alembic.ini current` | PASS command exit; authenticated API health provided exact applied migration list |
| Python dependency consistency | `docker compose run --rm --no-deps --entrypoint python nope-api -m pip check` | PASS: no broken requirements |
| Python advisory audit | `docker compose run --rm --no-deps -e TMPDIR=/app/.nope-workspaces --entrypoint pip-audit nope-api -r /app/apps/api/requirements.txt --progress-spinner off` | RESIDUAL: one `protobuf 4.25.9` / `PYSEC-2026-1805` advisory |
| Trivy production scan | `docker compose run --rm --no-deps -e TRIVY_CACHE_DIR=/app/.nope-workspaces/trivy-cache --entrypoint trivy nope-api fs --cache-dir /app/.nope-workspaces/trivy-cache --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 --skip-dirs /app/.nope-workspaces --skip-dirs /app/apps/api/tests/fixtures --skip-dirs /app/benchmarks /app` | PASS: 0 high/critical findings in production requirements path |

Warnings:

- Backend: FastAPI `on_event` deprecation warning.
- Backend: pytest-asyncio loop-scope deprecation warning.
- Frontend/Playwright: Node `NO_COLOR` ignored because `FORCE_COLOR` is set.
- Web build: known autoprefixer mixed-support warning.

No `xfail` tests were observed.

Skipped Playwright tests:

| File | Test family | Count | Reason | Completion impact |
| --- | --- | ---: | --- | --- |
| `apps/web/tests/e2e/visual.spec.ts` | `desktop visual for overview/findings/attack-map/coverage/assets/reports/settings` outside `chromium-1280` | 35 | Dense route screenshots are intentionally captured once at desktop width; shell snapshots, flows, accessibility, keyboard behavior, and responsive checks still run at every required width. | Does not block local completion. |

## Benchmark Results

| Mode | Command | Status | Expected | Actual | FP | FN | Precision | Recall | F1 | Duplicate count |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Scanner-only | `docker compose run --rm --no-deps nope-api python -m nope_api.benchmarks --mode scanner-only --output /tmp/nope-final-audit-scanner-only.json` | PASS | 41 | 79 | 0 | 0 | 1.0 | 1.0 | 1.0 | 40 |
| Scanner-plus-Qwen | `docker compose run --rm --no-deps -e NOPE_AI_PROVIDER=llama.cpp -e NOPE_QWEN_ENDPOINT=http://nope-ai:8080 nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-final-audit-scanner-plus-qwen.json` | PASS | 41 | 79 | 0 | 0 | 1.0 | 1.0 | 1.0 | 40 |

Duplicate count is related supporting scanner evidence tied to expected benchmark concepts; benchmark validation did not classify these as unexplained false positives.

## Scanner Matrix

| Scanner | Final audit status |
| --- | --- |
| NOPE rules | PASS |
| Semgrep | PASS |
| Gitleaks | PASS |
| OSV-Scanner | PASS |
| Trivy | PASS |
| Checkov | PASS |
| Bandit | PASS |
| Hadolint | PASS |
| OWASP ZAP | PASS for supported dynamic manifests through Stage 4/backend tests; not applicable to static repository scans and reported honestly |
| npm audit | PASS |
| pnpm audit | PASS; not applicable when no `pnpm-lock.yaml` exists |
| yarn audit | PASS; not applicable when no `yarn.lock` exists |
| pip-audit | PASS plugin behavior; production dependency advisory residual documented separately |
| .NET package audit | PASS plugin contract; CLI unavailable in image and reported honestly |
| cargo audit | PASS plugin contract; CLI unavailable in image and reported honestly |
| govulncheck | PASS plugin contract; CLI unavailable in image and reported honestly |
| composer audit | PASS plugin contract; CLI unavailable in image and reported honestly |
| bundler-audit | PASS plugin contract; CLI unavailable in image and reported honestly |

## Capability Matrix

| Capability | Status | Evidence |
| --- | --- | --- |
| Clean-room Docker startup | PASS | Fresh `down -v` plus `up --build -d`; all canonical services healthy/running |
| Local auth/session/logout | PASS | Backend tests and Playwright login/logout/session flows |
| Project folders and scan scoping | PASS | Backend ownership tests and Playwright folder flows |
| ZIP ingestion and hostile archive handling | PASS | Backend hostile archive tests |
| Queue/worker/events/recovery | PASS | Backend queue, Stage 2 event, restart, retry, cancellation, heartbeat tests |
| Static scanner pipeline | PASS | Full backend suite and scanner-only benchmark |
| Ecosystem scanner plugins | PASS | Full backend scanner/plugin tests and capability health |
| Dynamic/ZAP scanning | PASS | Stage 4 dynamic Node/Python/ZAP tests; static scans honestly mark ZAP not applicable |
| Sandbox boundary | PASS | Container inspection plus hostile sandbox tests |
| Qwen actions | PASS | Authenticated health, scanner-plus-Qwen benchmark, Stage 7 tests |
| RAG | PASS | Stage 7 tests; deterministic lexical/symbol/route/graph/finding-centered retrieval, no embeddings claimed |
| AI cache | PASS | Stage 7 cache restart/invalidation tests |
| Findings schema/dedupe/lifecycle | PASS | Stage 6 and full backend tests |
| Reports | PASS | Backend report/export tests |
| Baselines/history/drift | PASS | Backend drift/persistence tests and Playwright reports/drift flow |
| GitHub local contract | PASS | Backend fake-server/protocol tests and authenticated blocked-state check |
| GitHub external activation | BLOCKED | No real GitHub credentials supplied |
| Frontend | PASS | Lint/typecheck/build and Playwright flows |
| Accessibility | PASS | Axe route suite and keyboard/focus/modal/reduced-motion tests |
| Visual regression | PASS | Shell snapshots all widths and dense route screenshots at `chromium-1280`; intentional dedupe skips documented |
| NOPE self-security | PASS WITH RESIDUAL | Auth, CSRF/origin, CORS, rate limit, request limit, ownership, container, hostile-input tests pass; protobuf residual documented |
| Documentation | PASS | Canonical docs reviewed and stale final-audit labels corrected in this pass |
| Production SaaS readiness | OUT OF SCOPE / NOT CLAIMED | Requires production infrastructure, real secrets, TLS, backups, observability, incident process, and external credentials |

## Final Completion Percentages

| Area | Score |
| --- | ---: |
| Overall original-scope completion | 100% of locally achievable scope |
| Local-product completion | 100% locally achievable and verified |
| Core pipeline | 100% |
| Persistence | 100% |
| Queue and worker | 100% |
| Scan event durability | 100% |
| Static scanners | 100% |
| Ecosystem scanners | 100% local contract; missing ecosystem CLIs are honest unavailable states |
| Dynamic scanning | 100% for supported local manifests and authorized URL checks |
| Finding quality | 100% |
| Qwen | 100% local runtime path |
| RAG | 100% for the documented non-vector RAG design |
| AI cache | 100% |
| Reports | 100% |
| History and drift | 100% |
| Sandbox | 100% local runner-boundary design, with documented runner residual risk |
| GitHub local implementation | 100% |
| GitHub external activation | 0% activated / BLOCKED by missing real credentials |
| Frontend | 100% |
| Accessibility | 100% |
| Browser testing | 100% |
| Visual regression | 100% with intentional viewport deduplication |
| Backend tests | 100% passing |
| Security posture | Production-ready local-tool posture with documented residuals |
| Documentation | 100% for current local behavior and blocked states |

## Product Maturity Verdict

**Production-ready local tool.**

NOPE is not a production-ready SaaS. The local tool verdict is justified because clean-room startup is reproducible, benchmarks pass, hostile-input and sandbox boundaries are tested, durable events and recovery paths are covered, authorization is tested across sensitive objects, local Qwen/RAG works under the VRAM target, reports/drift/lifecycle are persisted and tested, and documentation distinguishes local completion from external activation.

## Remaining Defects

No new original-scope implementation defects were found in this adversarial pass.

## Remaining Blocked Items

- Real GitHub private repository activation: blocked until operator supplies real GitHub credentials/installations.
- Production SaaS readiness: outside local-product scope and not claimed.

## Residual Risks

- `pip-audit` reports `protobuf 4.25.9` / `PYSEC-2026-1805`; Trivy did not report a high/critical requirements vulnerability in the same final pass. This remains a documented scanner dependency-chain residual.
- `nope-runner` intentionally owns Docker daemon access for local sandbox/ZAP execution. API, worker, and web do not have the socket.
- Local Compose publishes development ports for operator access. Production deployment must private-bind data services and add TLS/secrets/backup/observability.
- First uncached Qwen latency remains hardware/model-bound; durable cache covers repeated equivalent requests.

## Final Honest Statement

Based on the commands above, NOPE deserves **100% locally achievable original-scope completion** and the maturity classification **Production-ready local tool**. The score is not a SaaS claim and not a real-GitHub-activation claim. It is earned by clean-room reproducibility, passing full backend/frontend/browser/security/benchmark checks, durable persistence and recovery coverage, tested hostile-input boundaries, working local Qwen under the VRAM target, and accurate documentation of the remaining external blocks and residual risks.
