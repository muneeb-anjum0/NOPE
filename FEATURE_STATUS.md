# NOPE Feature Status

Status values are limited to: Complete, Partially complete, Not implemented, Blocked by external dependency, Not applicable.

| Feature | Planned scope | Implementation status | Verification status | Tests | Known limitations | Remaining work |
| --- | --- | --- | --- | --- | --- | --- |
| Monorepo architecture | Web, API, worker, shared packages, scanners, docs, Docker | Partially complete | Verified locally | API tests, web lint/typecheck/build, Docker health | Persistence is development-first | Add production DB repository implementation |
| URL-only scan | Authorized black-box checks for headers, cookies, exposed paths, trackers, basic CORS | Partially complete | API health verified; endpoint implemented | URL scope tests | TLS depth and ZAP require external tooling | Add richer browser crawling and ZAP runtime |
| Repository-only scan | ZIP ingestion, stack detection, custom rules, dependency manifests, code graph, findings | Partially complete | Verified with vulnerable ZIP fixture | API tests and multipart smoke test | GitHub clone requires credentials; external scanners optional | Add GitHub App/OAuth production flow |
| Full scan | Repository plus URL plus optional AI and sandbox | Partially complete | Build verified; full endpoint implemented | API import/build tests | Dynamic testing is conservative; sandbox execution depends on Docker | Add isolated target app execution jobs |
| Authorization scope | Ownership confirmation, approved hosts, redirect/private IP protection | Partially complete | Verified by tests | URL scope tests | No authenticated user system yet | Add org/user auth and persisted audit trail |
| ZIP ingestion | Size/file limits, Zip Slip prevention, symlink handling, cleanup | Partially complete | Verified by tests | Zip Slip test | In-memory artifact metadata | Persist artifacts to object storage |
| GitHub integration | Adapter contract, repo metadata, PR workflow placeholders | Partially complete | Pending | Pending | Requires GitHub App/OAuth credentials | Implement GitHub App installation token flow |
| Stack detector | Languages, frameworks, data systems, deployment systems, evidence | Partially complete | Verified with fixture | Stack detector test | Heuristic detector, not AST-complete | Expand rules and fixtures |
| Attack surface | Routes, handlers, auth hints, validation, data/file/external calls | Partially complete | Verified with fixture | Attack surface test | Heuristic extraction for common frameworks | Add parser-backed extraction |
| Code graph | Files, functions, imports, routes, auth checks, sinks | Partially complete | Verified by scan smoke test | Pipeline smoke test | Lightweight graph, no full interprocedural analysis | Add language-specific AST graph builders |
| Scanner plugin architecture | Health checks, applicability, execution, normalization, failure behavior | Partially complete | Verified via health and scan smoke test | API smoke test | External scanner CLIs absent locally | Add scanner containers and version pinning |
| Semgrep plugin | Run Semgrep when installed; normalize SARIF/JSON | Partially complete | Pending | Pending | CLI not installed locally | Add containerized Semgrep image |
| Gitleaks plugin | Run Gitleaks when installed; normalize findings | Partially complete | Pending | Pending | CLI not installed locally | Add containerized Gitleaks image |
| OSV-Scanner plugin | Run OSV when installed | Partially complete | Pending | Pending | CLI not installed locally | Add lockfile coverage fixtures |
| Trivy plugin | Run Trivy when installed | Partially complete | Pending | Pending | CLI not installed locally | Add filesystem/container modes |
| Checkov plugin | Run Checkov when installed | Partially complete | Pending | Pending | CLI not installed locally | Add IaC fixtures |
| Hadolint plugin | Run Hadolint when installed | Partially complete | Pending | Pending | CLI not installed locally | Add Dockerfile fixture |
| Bandit plugin | Run Bandit when installed | Partially complete | Pending | Pending | CLI not installed locally | Add Python fixture |
| Ecosystem audits | npm/pnpm/yarn/pip/cargo/go/composer/bundler/dotnet adapters | Partially complete | Pending | Pending | Only manifest detection and adapter contract initially | Add lockfile-specific parser normalization |
| Custom rules | Secrets, authorization, auth, headers, CORS, Supabase, privacy, AI abuse | Partially complete | Verified with vulnerable fixture | Rules tests | Rules are heuristic and conservative | Expand pack versioning and tuning |
| Deduplication | Stable fingerprint, source merging, recurrence support | Partially complete | Verified by tests | Dedupe test | No persisted baseline yet | Add database-backed baselines |
| RAG | Focused evidence retrieval for findings | Partially complete | Import/build verified | API import test | Simple lexical retriever | Add embeddings/vector index optional adapter |
| Qwen adapter | Config, health, graceful failure, structured analysis contract | Partially complete | Verified as disabled/no-runtime path | API health | No local runtime/model found | Configure Ollama/llama.cpp endpoint and model file |
| Patch generation | Suggested fix and regression test contracts | Partially complete | Pending | Pending | No automatic repo mutation from UI | Add sandboxed patch branch workflow |
| Sandbox | Docker execution contract and compose services | Partially complete | Pending | Pending | Target app sandbox jobs not fully executed | Add per-scan container runner |
| Dynamic testing | Safe URL checks, headers, exposed paths, non-destructive probes | Partially complete | Pending | Pending | Browser/ZAP crawling not complete | Add ZAP baseline scan integration |
| Drift detection | Scan history comparison model | Partially complete | Pending | Pending | In-memory history only | Persist scans and baseline comparisons |
| Reporting | Web, JSON, Markdown, SARIF-like export | Partially complete | Pending | Pending | PDF not implemented | Add PDF generator |
| Dashboard UI | Premium compact app shell and product pages | Partially complete | Pending | Pending | Uses local API; auth not implemented | Add login/org/project management |
| Accessibility | Keyboard focus, ARIA labels, contrast, responsive layouts | Partially complete | Pending | Pending | Needs formal audit | Run axe/playwright checks |
| Observability | Structured logs, request IDs, scan IDs, scanner statuses | Partially complete | Pending | Pending | No centralized log backend | Add OpenTelemetry exporter |
| Resource controls | Repo, file, scanner, AI, URL, artifact limits | Partially complete | Pending | Pending | Limits are local config, not per-plan billing | Add org policy enforcement |
| Docker | Compose, web/API/worker/Postgres/Redis/MinIO, primary container name `NOPE` | Partially complete | Verified locally | `docker compose up --build -d`, health checks | Scanner images are not bundled | Add scanner service images and production gateway |
| Documentation | Architecture, security, development, deployment, API, feature status, worklog | Partially complete | Updated after verification | Documentation review | Needs future updates as features deepen | Keep status matrix current |
