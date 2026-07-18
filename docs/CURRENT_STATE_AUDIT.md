# NOPE Current State Audit

Date: 2026-07-18 06:03 Asia/Karachi
Commit audited: `a46bbc5 Enable base Docker AI runtime`
Branch: `main`

## 1. Executive verdict

NOPE is a functional local security-scanning MVP with real Dockerized scanners, PostgreSQL persistence, Redis worker execution, report exports, folder-scoped scans, and a live local Qwen/llama.cpp path. It is not production-ready and it is not yet a fully reliable scanner-quality product. The benchmark suite still fails: scanner-only and scanner-plus-Qwen both leave 2 unexpected false negatives, 14 known false negatives, and 22 benchmark false positives. The UI is broad and usable, but accessibility/browser automation is not formalized. GitHub private repository automation remains a blocked contract, not a working integration.

## 2. Overall completion percentage

| Area | Completion | Basis |
| --- | ---: | --- |
| Overall original scope | 72% | Local MVP exists, but benchmark quality, GitHub, dynamic testing, event observability, and production hardening remain incomplete. |
| Core pipeline | 78% | Real upload -> queue -> worker -> scanners -> evidence gate -> Qwen -> reports passed E2E. Benchmark quality still fails. |
| Frontend | 82% | Routes/build pass and UI is folder-scoped; formal a11y/e2e browser test automation is missing. |
| Backend | 82% | 94 backend tests pass and E2E scan works; API lint cannot run on host because `ruff` is absent. |
| Security tooling | 64% | Main scanner CLIs run in Docker, but benchmark false negatives and unimplemented audit-family tools remain. |
| AI/RAG | 70% | Qwen is live with 28 GPU layers and RAG context; first-run generation remains slow and cache is process/localStorage-based. |
| Test completion | 72% | Backend tests strong, frontend lint/type/build pass, but many tests use fakes and no full browser/axe/hostile sandbox matrix was run in this audit. |
| Documentation | 58% | Docs are extensive but historical status docs overclaim completion against current benchmark evidence. |

## 3. Current runnable state

A local user can start the app with plain `docker compose up --build -d`, open `http://localhost:3000`, log in locally, create a scan folder, upload a ZIP, let Redis/worker execute scanners, view findings/assets/reports/attack map/coverage, call Qwen Explain/Challenge/Fix/Test, and download JSON/Markdown/SARIF/PDF reports. In the audited E2E run, scan `scan_356656eeadfa4c6a` completed with 24 findings, Qwen review `Complete`, and all report formats returned HTTP 200.

## 4. What works fully

- Docker app/base compose now starts the AI layer by default: `nope-ai` uses CUDA llama.cpp, model `/models/Qwen3-8B-Q4_K_M.gguf`, `--n-gpu-layers 28`, and API/worker see `llama.cpp`.
- PostgreSQL migrations are applied: `0001_initial`, `0002_report_bodies`; pending/unexpected lists are empty.
- Frontend lint, typecheck, and production build passed.
- Backend full pytest suite passed: `94 passed, 2 warnings`.
- Scanner binaries exist in the API image: Semgrep 1.170.0, Gitleaks 8.28.0, OSV-Scanner 2.2.3, Trivy 0.72.0, Checkov 3.3.8, Hadolint 2.14.0, Bandit 1.9.4.
- Reports work for real scans: JSON, Markdown, SARIF, and PDF returned HTTP 200 in the E2E run.

## 5. What works partially

| Item | What works | What does not | Evidence | Completion |
| --- | --- | --- | --- | ---: |
| Scanner quality | Real scanner execution and normalization | Benchmark fails with 2 unexpected false negatives, 14 known false negatives, 22 benchmark false positives | Docker benchmark outputs | 64% |
| Qwen actions | Explain/Challenge/Fix/Test return structured output and cache repeats | First uncached output takes 34-46s on this GPU; cache is not durable across API restart | Latency profile | 70% |
| Queue/events | Worker executes queued scans | E2E scan events endpoint returned `event_count: 0` despite completion | E2E scan output | 68% |
| Attack map | Dedicated route exists and can render mapped graph data | Graph depth/precision remains heuristic and depends on scan evidence | Source and UI behavior | 70% |
| Sandbox | Docker sandbox runner exists with limits | ZAP/dynamic workflow is opt-in/skipped for ordinary repo scans; hostile matrix not rerun | E2E scanner run skipped sandbox | 60% |
| GitHub | Settings/contracts/blocked adapter exist | No real OAuth/App token exchange or private repo access | Code/docs/routes | 35% local, 0% activated |

## 6. What only appears implemented

- GitHub private repository automation: routes/settings exist, but real repository listing and PR workflow are blocked.
- Command palette: requested in audit scope, but no verified implementation evidence found.
- npm/pnpm/yarn/pip/dotnet/cargo/govulncheck/composer/bundler audit as first-class scanners: mostly absent as dedicated plugins, partially covered by OSV/Trivy.
- Production auth: local auth works, but it is not production identity management.
- "Complete scanner quality": contradicted by benchmark failures.
- Durable AI action cache: UI localStorage and API memory cache help, but API restart clears server cache.

## 7. What is broken

- Benchmark quality gate is broken/failing. Reproduction: `docker compose exec -T nope-api python -m nope_api.benchmarks --mode scanner-only` and `--mode scanner-plus-qwen`; both exit 1.
- Host API lint is broken due missing host dependency. Reproduction: `pnpm api:lint`; result: `'ruff' is not recognized`.
- Scan event observability is incomplete. Real E2E scan completed, but `/events` returned zero events.

## 8. What is missing

Priority order: benchmark false-negative closure; durable event/progress history; real GitHub credential flow; scanner-family expansion; formal browser/axe tests; durable AI action cache; deeper attack graph/data-flow; production security hardening.

## 9. What is blocked externally

Real GitHub private access requires GitHub App/OAuth credentials and installation verification. Production deployment requires real secrets, TLS, identity policy, hardened CORS/cookies, and container security review. Faster first-token/first-answer Qwen responses require faster GPU/runtime/model or shorter outputs; without quality sacrifices, local 8B GGUF generation remains around 8-9 tokens/sec here.

## 10. Phase completion table

See `docs/PHASE_COMPLETION_AUDIT.md`.

## 11. Capability matrix

See `docs/CAPABILITY_MATRIX.md`.

## 12. Scanner matrix

See `docs/CAPABILITY_MATRIX.md`.

## 13. Qwen and RAG status

Qwen is partially-to-strongly connected locally. Current Docker health reports `provider=llama.cpp`, runtime `http://nope-ai:8080`, model `qwen3-8b-q4-k-m`, GPU layers `28`, target `5000 MB`, and `nvidia-smi` showed `4049/6144 MiB`. Direct action generation works. Latency is inherent: uncached Explain/Challenge/Fix/Test measured 35.58s, 45.74s, 37.49s, 33.97s after safe optimization. Repeated same action measured 0.0s from cache. RAG is real lexical/graph retrieval, not embeddings/vector search.

## 14. Database and persistence status

Postgres is live and healthy. Migration status is clean. Scans, findings, reports, settings, baselines, sessions, and projects persist through the store layer. Remaining concerns: some tables/behaviors are dynamically created in code, JSON snapshots carry much of the object shape, and restart-persistence was not exhaustively tested in this run beyond Docker service continuity and database migration status.

## 15. Queue and worker status

Redis and worker are live. E2E scan ran through the worker and completed. Retry/cancel are covered by tests, but live retry/cancel and worker-restart behavior were not rerun in this audit. Event history is weak: E2E `/events` returned zero events.

## 16. Reporting status

Report generation is functional for JSON, Markdown, SARIF, and PDF. E2E report sizes: JSON 252,769 bytes, MD 11,375 bytes, SARIF 24,606 bytes, PDF 71,276 bytes. Reports are generated on request, not a separately queued async report job.

## 17. History and drift status

Folder-scoped scans and baseline/drift code exist and are tested. The model correctly avoids comparing different project folders. Remaining work: more transparent UI around baseline choice, arbitrary comparison ergonomics, and more robust fingerprint stability across code moves.

## 18. Sandbox status

Sandbox support exists with non-root launched containers, limited memory/CPU/PIDs, read-only repo mounts, no-new-privileges, and network off by default. However, the worker container itself runs as root and mounts `/var/run/docker.sock` to launch sibling containers. That is a major trust boundary risk for a tool that processes hostile repos. Dynamic/ZAP checks were skipped in the audited repository E2E.

## 19. UI and UX status

The UI is feature-rich and recently refined: landing page, folder-scoped scans, findings, attack map, coverage, assets, reports, settings, responsive sidebar, and route animations exist. Build passes. Remaining gaps: formal accessibility testing, browser interaction regression tests, and continued polish for dense data states.

## 20. Test status

Backend: `94 passed, 2 warnings`. Frontend: lint/typecheck/build pass. Focused AI tests: `13 passed`. Warnings: FastAPI `on_event` deprecation and pytest-asyncio loop-scope deprecation. Host API lint failed because `ruff` is not installed. Benchmarks fail. No skipped/xfail count was reported by pytest output.

## 21. Docker status

Plain `docker compose up --build -d` works. Services: `NOPE` web healthy on 3000, `nope-api` healthy on 8000, `nope-ai` healthy on 127.0.0.1:8081, Postgres healthy on 5432, Redis healthy on 6379, MinIO healthy on 9000/9001, worker running. Base compose now starts AI without requiring the GPU override file.

## 22. Documentation accuracy

Historical docs that call phases "Complete" are too optimistic against current benchmark evidence. Qwen runtime claims are now true for base Docker after commit `a46bbc5`; older docs saying special GPU profile is required are stale. Scanner docs should disclose benchmark failures and false-negative categories.

## 23. Security posture of NOPE itself

Local posture is acceptable for trusted developer use, not production. Strengths: ZIP Slip/symlink checks, SSRF/private-target blocking by default, bearer auth, Postgres ownership scoping, scanner output redaction, sandbox limits. Risks: worker Docker socket/root, local auth only, in-memory login rate limit, llama.cpp no API key/CORS warning, no formal container vulnerability audit, no production CSRF/cookie hardening review.

## 24. Technical debt

See `docs/TECHNICAL_DEBT.md`.

## 25. Recommended next sequence

1. Close benchmark false negatives and recalibrate false positives.
2. Fix durable queue/event progress.
3. Harden sandbox/worker Docker socket boundary.
4. Add formal browser/axe E2E.
5. Implement real GitHub activation once credentials exist.
6. Add durable AI action cache or user-visible async generation queue.

## 26. Fastest path to a genuinely complete local product

Make benchmarks pass, keep Docker base compose as the canonical runtime, add event persistence tests, run a hostile sandbox matrix, add Playwright smoke tests for all app routes, and document exact local setup around model path/VRAM.

## 27. Git and repository state

Branch: `main`. Commit: `a46bbc5`. Remote: `https://github.com/muneeb-anjum0/NOPE.git`. At audit collection time, implementation was pushed and branch matched origin. Audit documents are local working-tree additions until committed separately. Last stable code commit: `a46bbc5`.

## 28. Final evidence-based assessment

NOPE is a Functional MVP moving toward a strong local beta. It is not a production-ready local tool yet because scanner quality gates fail, dynamic testing is opt-in/skipped for common runs, the worker Docker socket boundary is risky, and formal browser/security regression coverage is incomplete. It is definitely not production-ready SaaS.

## 29. Stage 1 addendum: benchmark correctness

Date: 2026-07-18

After the original forensic audit, Stage 1 benchmark correctness was implemented and verified. Scanner-only and scanner-plus-Qwen benchmark modes now pass in the canonical Docker environment with precision, recall, and F1 of `1.000`, `0` false positives, `0` false negatives, and `0` known false negatives. The next unresolved completion-program item is Stage 2 durable scan event/progress history; the completed E2E scan event defect from the original audit is not yet fixed.
