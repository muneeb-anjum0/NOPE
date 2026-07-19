# NOPE Feature Status

Date: 2026-07-19
Baseline for final Stage 12 audit: `6267b3c6b05c0671d2d311876b3b25f3e4885dd1`

Status values are evidence-based: Complete, Locally complete, Externally blocked, Partial, or Out of scope.

| Feature | Status | Evidence | Remaining limit |
| --- | --- | --- | --- |
| Local Docker app startup | Locally complete | Compose starts web, API, worker, runner, Postgres, Redis, MinIO, and local Qwen. | Production deployment still needs real secrets, TLS, and private service bindings. |
| ZIP repository scanning | Complete | Hardened ingestion, worker execution, scanner normalization, reports, and tests. | Scan only authorized repositories. |
| Authorized URL scanning | Complete for non-destructive local scope | Scope checks, SSRF controls, redirects, response limits, and coverage states are tested. | Authenticated crawling of arbitrary production apps is not included. |
| Dynamic/ZAP scanning | Locally complete for supported manifests | Stage 4 tests prove supported Node/Python fixtures, private network, ZAP artifacts, alerts, and teardown. | Requires `.nope/sandbox.json`; unsupported stacks are reported honestly. |
| Postgres persistence | Complete | Migrations through `0005_ai_actions`; scans, findings, events, reports, lifecycle, GitHub contracts, and AI jobs/cache are durable. | Backups are operator responsibility. |
| Redis queue/worker | Complete | Durable scan events, retry, cancellation, stuck-worker recovery, and heartbeat tests. | Redis is transport/coordination; Postgres is authoritative for durable state. |
| Worker/sandbox security | Locally complete | General worker is non-root and socketless; `nope-runner` owns a narrow Docker boundary with allowlists and limits. | Runner still has Docker daemon authority by design in local Compose. |
| Scanner orchestration | Complete for local product scope | Deterministic rules, bundled scanners, ecosystem plugins, parser tests, artifact preservation, and benchmarks. | Some ecosystem CLIs report unavailable unless installed in the scanner image. |
| Benchmark correctness | Complete | Scanner-only and scanner-plus-Qwen benchmark gates reached 41/41 true positives, 0 FP/FN, F1 1.000 in Stage 1 evidence. | Scanner-plus-Qwen CI activation requires model/GPU availability. |
| Finding quality/lifecycle | Complete | Canonical schema, fingerprints, dedupe/correlation, lifecycle states, suppression expiry, audit history, and reintroduction tests. | More semantic graph precision can improve future quality. |
| Qwen actions | Complete | Explain, Challenge, Fix, Regression Test, and Patch Review run as durable jobs with structured validation, retries, cancellation, and 24h cache. | First uncached answer speed is hardware/model-bound. |
| RAG | Complete without embeddings | Lexical, symbol, graph, route, and finding-centered retrieval with provenance, redaction, prompt-injection tests, and limits. | Embeddings/vector search are intentionally not part of current design. |
| Reports | Complete | Web, JSON, Markdown, SARIF, and PDF reports use persisted data, redaction, ownership, retryable status, and MinIO artifacts. | Very large reports may still take noticeable local CPU time. |
| Baselines/drift | Complete | Latest-vs-previous, latest-vs-baseline, arbitrary comparison, recurrence/reintroduction, and version-change tests. | Incremental scan metadata is conservative and advisory. |
| GitHub integration | Locally complete; external activation blocked | Encrypted credentials, state/callback validation, repository listing/snapshot contracts, policy checks, fake-server protocol tests. | Real github.com private access requires operator credentials/installations. |
| Browser E2E/a11y/visual | Complete for deterministic local test scope | Stage 8 Playwright, axe, keyboard, mobile, and visual snapshot suites. | Tests run in fixture mode for deterministic browser state. |
| NOPE self-security | Locally complete with documented residual | Stage 11 auth, CSRF/origin, rate limit, request limit, headers, container, dependency, and security tests. | Documented protobuf scanner-chain residual and local runner Docker risk remain. |
| Documentation | In Stage 12 verification | README and canonical docs now reflect local scope, external blocks, residual risk, and commands. | Final clean-room evidence is recorded in `docs/FINAL_CLEAN_ROOM_AUDIT.md`. |

Product classification after Stage 11 approval and before final Stage 12 verification: **Strong local beta candidate**, not production-ready SaaS.
