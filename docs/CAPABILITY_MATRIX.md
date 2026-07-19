# NOPE Capability Matrix

Date: 2026-07-19
Current source-of-truth companion to the GitHub-facing README. Historical stage evidence lives in [`audits/`](audits/).

| Capability | Local-product status | Evidence | External or production limit |
| --- | --- | --- | --- |
| Docker startup | Locally complete | `docker compose up --build -d` starts the canonical stack, including `nope-ai` when the documented model mount exists. | Production requires real secrets, TLS, private data-service bindings, and backup policy. |
| ZIP ingestion | Complete | Hostile archive tests cover traversal, symlink, hardlink/special file, Unicode/case collision, bombs, nesting, size, count, and cleanup. | Operator must scan only authorized code. |
| URL scanning | Complete for non-destructive checks | Scope, SSRF, DNS recheck, port, redirect, timeout, and response-size tests pass. | Authenticated production crawling is not part of current scope. |
| Queue and durable progress | Complete | `scan_events` persists ordered, idempotent scan/stage/scanner/retry/cancel/worker/report/Qwen transitions and paginated replay. | Redis is not authoritative for historical state. |
| Worker sandbox boundary | Locally complete | Worker is socketless/non-root; runner owns token-authenticated allowlisted Docker execution with limits and cleanup. | Runner compromise remains a Docker-host risk in local Compose. |
| Dynamic/ZAP scanning | Locally complete for supported manifests | Supported Node/Python fixtures build/start in isolated containers; ZAP runs on a private network and stores version/config/raw alerts/findings. | Unsupported stacks and unauthenticated coverage are reported as skipped/partial/failed. |
| Scanner plugins | Complete for configured local image | Semgrep, Gitleaks, OSV, Trivy, Checkov, Hadolint, Bandit, npm, pnpm, yarn, pip-audit, dotnet, cargo, govulncheck, composer, and bundler plugin contracts exist with parsers/failure states. | Some ecosystem CLIs are unavailable unless installed; NOPE reports that honestly. |
| Benchmarks | Complete | Scanner-only and scanner-plus-Qwen benchmarks met 41/41 expected findings, 0 FP/FN, precision/recall/F1 1.000. | Qwen benchmark requires local model/GPU runtime. |
| Finding quality | Complete | Canonical schema, provenance, source metadata, stable fingerprints, dedupe, correlation, lifecycle, suppression expiry, recurrence, and reintroduction tests. | Future parser-backed semantic graphing can improve root-cause precision. |
| Reports | Complete | JSON, Markdown, SARIF, and PDF reports use persisted data, redaction, partial/failed coverage honesty, durable status, retry, and ownership checks. | Large local PDFs can take time on slow hardware. |
| Drift and baselines | Complete | Latest-vs-previous, latest-vs-baseline, arbitrary comparison, version changes, recurrence, reintroduction, and cleanup tests. | Incremental scan support remains conservative advisory metadata. |
| Qwen actions | Complete | Durable async jobs, structured JSON validation with retries, cancellation, 24h cache, cache invalidation, and UI state support. | First uncached generation speed is hardware/model-bound. |
| RAG | Complete without vector search | Lexical, symbol, route, graph, and finding-centered retrieval with provenance, trust boundaries, token/file/chunk/depth limits, and prompt-injection tests. | Embeddings/vector search are intentionally excluded. |
| GitHub | Locally complete; external activation blocked | Encrypted credential storage, OAuth/App-compatible state/callback validation, repository listing/snapshot contracts, policy checks, disconnect/revocation, audit, and fake-server protocol tests. | Real private repo access requires operator GitHub credentials and installation. |
| Frontend | Complete for local product scope | Playwright covers core flows, mobile widths, accessibility checks, keyboard behavior, visual snapshots, and fixture-mode deterministic states. | Fixture mode is used for deterministic browser CI. |
| NOPE self-security | Locally complete with residuals | Auth/session/rate-limit/CSRF-origin/CORS/request-limit/container/dependency/security tests and docs. | Documented protobuf scanner-chain advisory and local Docker runner residual risk. |
| Documentation | Complete with documented residuals | README and canonical docs describe behavior, commands, blocked integrations, out-of-scope items, residual risks, and verification evidence. | Future docs must keep external GitHub activation and production-SaaS readiness separate from local-product completion. |

## Scanner Matrix

| Scanner | Applicability | Output | Failure handling | Local status |
| --- | --- | --- | --- | --- |
| NOPE rules | Source/security pattern rules | Canonical findings and candidate audit | Candidates can be promoted, rejected, or withheld | Complete |
| Semgrep | Source patterns | JSON | Failed/unavailable status and raw output | Complete |
| Gitleaks | Repository secrets | JSON | Redacted raw output and coverage reduction | Complete |
| OSV-Scanner | Lockfiles/dependencies | JSON | Failed/unavailable status | Complete |
| Trivy | Dependencies, containers, IaC, secrets | JSON | Failed/unavailable status | Complete |
| Checkov | IaC/config | JSON | Failed/unavailable status | Complete |
| Hadolint | Dockerfiles | JSON/checkstyle-style parser path | Failed/unavailable status | Complete |
| Bandit | Python security | JSON | Failed/unavailable status | Complete |
| npm audit | `package-lock.json` | JSON | Unavailable when npm cannot run | Complete |
| pnpm audit | `pnpm-lock.yaml` | JSON | Unavailable when pnpm cannot run | Complete |
| yarn audit | `yarn.lock` | JSON/NDJSON | Unavailable when yarn cannot run | Complete |
| pip-audit | Python manifests | JSON | Unavailable when pip-audit cannot run | Complete |
| dotnet package audit | `.csproj`/solution manifests | JSON | SDK absence reported | Complete plugin; tool external |
| cargo audit | `Cargo.lock` | JSON | cargo-audit absence reported | Complete plugin; tool external |
| govulncheck | `go.mod` | NDJSON | govulncheck absence reported | Complete plugin; tool external |
| composer audit | `composer.lock` | JSON | Composer absence reported | Complete plugin; tool external |
| bundler-audit | `Gemfile.lock` | JSON | bundler-audit absence reported | Complete plugin; tool external |
| OWASP ZAP | `.nope/sandbox.json` dynamic target | JSON | skipped/partial/failed states | Complete for supported manifests |
