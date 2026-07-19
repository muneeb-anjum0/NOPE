# NOPE Technical Debt

Human note: this doc is meant to explain the thing plainly. If something is still limited or local-only, I would rather say that out loud than hide it behind shiny wording.


Date: 2026-07-19

This file tracks current known debt and explicit external blocks. Historical fixed items are preserved in `docs/audits/IMPLEMENTATION_WORKLOG.md`.

## High

- **Production deployment hardening:** local Compose is suitable for trusted local operation, but production needs real secrets, TLS, backups, private service bindings, monitoring, and a hardened runner deployment.
- **Runner residual risk:** `nope-runner` intentionally owns Docker daemon access for local sandbox/ZAP execution. The general worker is socketless, but a runner compromise is still a Docker-host compromise. Production should use rootless Docker, an authorization proxy, or a separate runner host.
- **Python dependency residual:** `pip-audit` reports `protobuf 4.25.9` / `CVE-2026-0994` through the Semgrep/OpenTelemetry scanner chain. The documented fix requires protobuf 5/6 while the current scanner dependency path pins `<5`.

## Medium

- **Qwen first uncached latency:** durable caching removes repeated latency, but first-generation Explain/Challenge/Fix/Test actions remain bounded by the local 8B GGUF model and GPU throughput.
- **Attack graph precision:** graph generation is useful and tested, but deeper interprocedural AST/data-flow precision can improve future root-cause paths.
- **Authenticated dynamic crawling:** NOPE supports manifest-declared internal ZAP baseline scans and reports unauthenticated/partial states honestly. Full authenticated browser crawling is future scope.
- **Operational observability:** health endpoints, durable events, and reports exist, but production metrics dashboards and centralized logs are not included.

## Low

- FastAPI `on_event` deprecation warning.
- pytest-asyncio default fixture loop-scope deprecation warning.

## Externally Blocked

- Real GitHub private repository activation requires operator-provided GitHub App/OAuth/token credentials and repository installation. Local contracts and protocol tests are complete.

## Out Of Scope For Local Product Completion

- Payments, billing, subscriptions, email delivery, enterprise SSO, multi-region architecture, formal compliance certification, guaranteed security, and production SaaS operations.
