# NOPE Current State Audit

Date: 2026-07-19
Stage 12 pre-stage commit: `6267b3c6b05c0671d2d311876b3b25f3e4885dd1`
Branch: `main`

## Executive Verdict

NOPE is a strong local-beta security scanning platform after Stage 11 approval. The local product has durable persistence, queue/worker execution, scanner orchestration, hardened ZIP/URL handling, a narrow sandbox runner boundary, optional ZAP dynamic scans for supported manifests, first-class finding lifecycle, reports, baselines/drift, deterministic browser tests, and local Qwen/RAG actions.

It is not production-ready SaaS. Real GitHub private repository activation is locally implemented but externally blocked until credentials are configured and verified. Production deployment still needs real secrets, TLS, backups, monitoring, private service exposure, and a hardened runner deployment.

## What Works Locally

- Docker Compose starts the canonical local stack: web, API, worker, runner, Postgres, Redis, MinIO, and Qwen.
- Local login creates and uses Postgres-backed users and SHA-256-stored session tokens.
- Project folders own their scans, findings, reports, baselines, and drift.
- ZIP scans use hardened extraction and run through Redis worker jobs.
- URL scans are authorized, non-destructive, and SSRF/redirect/size/port scoped.
- Dynamic ZAP scans run for supported `.nope/sandbox.json` Node/Python manifests on a private network.
- Durable `scan_events` reconstruct progress after browser/API/worker restarts.
- Findings are canonicalized, deduplicated, lifecycle-managed, audited, suppressible, and recurrence-aware.
- Reports are generated from persisted data in JSON, Markdown, SARIF, and PDF.
- Qwen actions are durable, cacheable for 24 hours, evidence-grounded, and failure-safe.
- Browser E2E, accessibility, visual, backend, security, and benchmark suites exist.

## What Is Blocked Externally

| Area | Block | Local work completed |
| --- | --- | --- |
| GitHub private activation | Requires real GitHub App/OAuth/token credentials and repository installation. | Encrypted credentials, state/callback validation, repository listing/snapshot contracts, branch/default SHA capture, policy checks, ownership, disconnect/revocation, fake-server protocol tests. |
| Scanner-plus-Qwen CI | Requires a CI runner with the GGUF model mount and GPU/CPU capacity. | Local Docker command and benchmark path exist. |

## Production-SaaS Limits

The following are outside the local-product completion scope and must not be claimed as done:

- TLS termination and external ingress hardening.
- Managed identity/SSO and tenant administration.
- Backups, disaster recovery, and retention operations.
- Centralized metrics/logs/alerting.
- Separate hardened runner host or rootless Docker deployment.
- Billing, email, subscriptions, and commercial SaaS operations.

## Residual Risks

- `nope-runner` owns Docker daemon access in local Compose. The worker/API/web do not, but runner compromise is still high-impact.
- `pip-audit` reports a documented `protobuf 4.25.9` scanner-chain residual through Semgrep/OpenTelemetry; the compatible fix requires upstream dependency movement.
- First uncached Qwen responses remain hardware/model-bound. Durable cache removes repeated equivalent latency.
- Dynamic ZAP coverage is unauthenticated unless the supported manifest supplies enough runtime context; NOPE reports partial/skipped/failure states honestly.

## Final Audit Status

Stage 12 is responsible for replacing stale claims, verifying documented commands from a clean environment, running the full regression/benchmark/security matrix, committing final cleanup, and producing the final completion report. Evidence is recorded in `docs/FINAL_CLEAN_ROOM_AUDIT.md`.
