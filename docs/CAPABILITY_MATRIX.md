# NOPE Capability Matrix

Date: 2026-07-19
This is the companion table to the GitHub-facing README. Older build/audit notes live in [`audits/`](audits/).

| Capability | Local-product status | Evidence | External or production limit |
| --- | --- | --- | --- |
| Docker startup | Works locally | `docker compose up --build -d` starts the standard stack, including `nope-ai` when the documented model mount exists. | Production requires real secrets, TLS, private data-service bindings, and backup policy. |
| ZIP ingestion | Works | Hostile archive tests cover traversal, symlink, hardlink/special file, Unicode/case collision, bombs, nesting, size, count, and cleanup. | Operator must scan only authorized code. |
| URL scanning | Works for non-destructive checks | Scope, SSRF, DNS recheck, port, redirect, timeout, and response-size tests pass. | Authenticated production crawling is not part of current scope. |
| Queue and durable progress | Works | `scan_events` persists ordered, idempotent scan/stage/scanner/retry/cancel/worker/report/Qwen transitions and paginated replay. | Redis is not authoritative for historical state. |
| Worker sandbox boundary | Works locally | Worker is socketless/non-root; runner owns token-authenticated allowlisted Docker execution with limits and cleanup. | Runner compromise remains a Docker-host risk in local Compose. |
| Dynamic/ZAP scanning | Works locally for supported manifests | Supported Node/Python fixtures build/start in isolated containers; ZAP runs on a private network and stores version/config/raw alerts/findings. | Unsupported stacks and unauthenticated coverage are reported as skipped/partial/failed. |
| Scanner plugins | Works in the configured local image | Semgrep, Gitleaks, OSV, Trivy, Checkov, Hadolint, Bandit, npm, pnpm, yarn, pip-audit, dotnet, cargo, govulncheck, composer, and bundler plugin contracts exist with parsers/failure states. | Some ecosystem CLIs are unavailable unless installed; NOPE reports that plainly. |
| Rules v2 | Works locally with honest limits | 100+ rule catalog, upgraded first-party rules, candidate generation, promotion decisions, owner-scoped APIs, dashboard review, reports, and Stage 13 tests. | Candidate records live in the scan JSON snapshot; several catalog families still use broad text/graph heuristics rather than AST-grade per-framework dataflow. |
| Benchmarks | Passing locally and in CI for scanner-only | Scanner-only and scanner-plus-Qwen benchmarks met 41/41 expected findings, 0 FP/FN, precision/recall/F1 1.000. | Qwen benchmark requires local model/GPU runtime. |
| Finding quality | Works | Shared finding schema, provenance, source metadata, stable fingerprints, dedupe, correlation, lifecycle, suppression expiry, recurrence, and reintroduction tests. | Future parser-backed semantic graphing can improve root-cause precision. |
| Reports | Works | JSON, Markdown, SARIF, and PDF reports use persisted data, redaction, partial/failed coverage honesty, durable status, retry, and ownership checks. | Large local PDFs can take time on slow hardware. |
| Drift and baselines | Works | Latest-vs-previous, latest-vs-baseline, arbitrary comparison, version changes, recurrence, reintroduction, and cleanup tests. | Incremental scan support remains conservative advisory metadata. |
| Qwen actions | Works when the model is mounted | Durable async jobs, structured JSON validation with retries, cancellation, 24h cache, cache invalidation, and UI state support. | First uncached generation speed is hardware/model-bound. |
| RAG | Works without vector search | Lexical, symbol, route, graph, and finding-centered retrieval with provenance, trust boundaries, token/file/chunk/depth limits, and prompt-injection tests. | Embeddings/vector search are intentionally excluded. |
| GitHub | Local contracts work; external activation blocked | Encrypted credential storage, OAuth/App-compatible state/callback validation, repository listing/snapshot contracts, policy checks, disconnect/revocation, audit, and fake-server protocol tests. | Real private repo access requires operator GitHub credentials and installation. |
| Frontend | Works for local product scope | Playwright covers core flows, mobile widths, accessibility checks, keyboard behavior, visual snapshots, and fixture-mode deterministic states. | Fixture mode is used for deterministic browser CI. |
| NOPE self-security | Works locally with residuals | Auth/session/rate-limit/CSRF-origin/CORS/request-limit/container/dependency/security tests and docs. | Documented protobuf scanner-chain advisory and local Docker runner residual risk. |
| Documentation | Current docs are cleaned up | README and docs describe behavior, commands, blocked integrations, out-of-scope items, residual risks, and verification evidence. | Future docs must keep external GitHub activation and production-SaaS readiness separate from local-product claims. |

## Scanner Matrix

| Scanner | Applicability | Output | Failure handling | Local status |
| --- | --- | --- | --- | --- |
| NOPE rules | Source/security pattern rules | NOPE findings and candidate audit | Candidates can be promoted, rejected, or withheld | Wired |
| Semgrep | Source patterns | JSON | Failed/unavailable status and raw output | Wired |
| Gitleaks | Repository secrets | JSON | Redacted raw output and coverage reduction | Wired |
| OSV-Scanner | Lockfiles/dependencies | JSON | Failed/unavailable status | Wired |
| Trivy | Dependencies, containers, IaC, secrets | JSON | Failed/unavailable status | Wired |
| Checkov | IaC/config | JSON | Failed/unavailable status | Wired |
| Hadolint | Dockerfiles | JSON/checkstyle-style parser path | Failed/unavailable status | Wired |
| Bandit | Python security | JSON | Failed/unavailable status | Wired |
| npm audit | `package-lock.json` | JSON | Unavailable when npm cannot run | Wired |
| pnpm audit | `pnpm-lock.yaml` | JSON | Unavailable when pnpm cannot run | Wired |
| yarn audit | `yarn.lock` | JSON/NDJSON | Unavailable when yarn cannot run | Wired |
| pip-audit | Python manifests | JSON | Unavailable when pip-audit cannot run | Wired |
| dotnet package audit | `.csproj`/solution manifests | JSON | SDK absence reported | Wired; tool external |
| cargo audit | `Cargo.lock` | JSON | cargo-audit absence reported | Wired; tool external |
| govulncheck | `go.mod` | NDJSON | govulncheck absence reported | Wired; tool external |
| composer audit | `composer.lock` | JSON | Composer absence reported | Wired; tool external |
| bundler-audit | `Gemfile.lock` | JSON | bundler-audit absence reported | Wired; tool external |
| OWASP ZAP | `.nope/sandbox.json` dynamic target | JSON | skipped/partial/failed states | Wired for supported manifests |
