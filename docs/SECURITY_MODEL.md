# NOPE Security Model

NOPE treats every uploaded repository and every scanned target as potentially hostile.

## Authorization boundaries

- URL scans require explicit authorization confirmation.
- API routes use bearer tokens from the local login flow; state-changing requests with a browser `Origin` header must come from an allowlisted web origin.
- Local session tokens are stored as SHA-256 digests, expire, and are deleted on logout.
- Login brute-force protection uses Redis-backed shared counters when Redis is available and falls back to process-local counters only if Redis is unreachable.
- Public `/health` is intentionally sanitized. Detailed database, scanner, AI, and sandbox health is available only through authenticated API routes.
- Approved hosts are derived from the requested target and optional scope settings.
- Redirects to unrelated domains are blocked.
- Private IP and localhost targets are blocked by default unless local sandbox scanning is explicitly enabled.
- Destructive testing is disabled by default.

## Upload boundaries

- API requests with excessive `Content-Length` are rejected before route handling.
- ZIP extraction rejects absolute paths and `..` traversal.
- Symlinks, hardlinks/special files, duplicate normalized paths, excessive path length, excessive nesting, oversized compressed archives, oversized extracted content, high compression-ratio archives, and excessive file counts are rejected.
- ZIP paths are normalized before extraction so Unicode and case tricks cannot create duplicate or escaping members.
- Temporary workspaces are isolated and cleaned up after failed extraction or scan completion.

## Execution boundaries

- Unknown application code is not executed by the API process.
- The general worker is non-root in the Compose stack and does not mount the Docker socket.
- A dedicated internal `nope-runner` service owns the Docker socket boundary. The worker can request only a sandbox assessment for an existing workspace under `NOPE_TEMP_ROOT`; the runner rejects unauthenticated requests and workspace paths outside that root.
- Repository sandbox workflows run in disposable Docker containers with non-root users, `no-new-privileges`, dropped capabilities, read-only repository mounts, read-only roots where supported, tmpfs work directories, memory/CPU/PID limits, bounded logs, and command timeouts.
- Sandbox workflow containers do not receive the Docker socket, host home, NOPE MinIO/Postgres/Redis/Qwen secrets, or privileged mode.
- Repository workflow images and commands must match configured allowlists; arbitrary images, commands, environment variables, mounts, and networks are not accepted.
- Network is disabled for repository workflows.
- ZAP dynamic scans use a private internal Docker network: one constrained application container is started from the declared manifest, one ZAP container scans only that internal target, and both are removed after the run.
- The ZAP scanner image keeps its writable root filesystem because the upstream image writes runtime files during startup; it still receives dropped capabilities, `no-new-privileges`, private-network-only access, tmpfs work paths, and memory/PID/time limits.
- Dynamic scans perform readiness checks before ZAP, capture ZAP version/config/raw JSON as bounded artifacts, parse alerts into normal findings, and mark unauthenticated, skipped, partial, failed-build, failed-startup, readiness, timeout, and crash states explicitly.
- Target application containers and scanner containers are separated in the architecture.

## URL boundaries

- URL scans require explicit authorization confirmation.
- Only `http` and `https` schemes are accepted.
- Credentials in URLs are rejected.
- Target ports are restricted to the configured allowlist.
- Hostnames are resolved and checked before scanning; private, loopback, link-local, reserved, localhost, and metadata-address targets are blocked by default.
- Redirects are not followed by default; unsafe redirect targets are reported instead of fetched.
- Probe requests use bounded timeouts and response-size limits.

## Residual risk

- The default Compose file is still a local-development deployment and publishes Postgres, Redis, MinIO, API, web, and llama.cpp ports on localhost for operator access and debugging. Production deployments should bind data services to private networks only, use real secrets/TLS, and restrict host firewall exposure.
- The local `nope-runner` service still holds Docker daemon authority because local Docker sandboxing requires a daemon boundary. A runner compromise can become a Docker-host compromise. The important design choice is that the general worker, API, web app, scanner code, and uploaded repositories no longer receive unrestricted Docker daemon access.
- Rootless Docker, a Docker authorization proxy, or a separate runner host would further reduce this residual risk in production deployments.
- ZAP runs on a runner-created internal Docker network only when a repository explicitly opts in with a sandbox manifest.
- `nope-runner` remains root inside its own container because it must reach the Docker socket. The general API, worker, and web services run non-root with dropped capabilities, `no-new-privileges`, read-only roots, tmpfs scratch space, and CPU/memory/PID limits.
- Dependency scan residual: `pip-audit` reports `protobuf 4.25.9` / `CVE-2026-0994` (`PYSEC-2026-1805`) through the Semgrep/OpenTelemetry scanner dependency chain. The fixed protobuf versions are `5.29.6` or `6.33.5`, while the installed `opentelemetry-proto 1.25.0` requires `protobuf<5`. NOPE does not expose protobuf JSON parsing as a user-facing API path, scanner execution is time/resource bounded, and this residual should be removed when Semgrep's compatible dependency chain supports protobuf 5+.

## Secrets

- Logs are redacted with aggressive secret patterns.
- Findings display masked secret evidence, not full values.
- Test identity secrets, GitHub OAuth secrets, GitHub private keys, and webhook secrets are encrypted before persistence and are not returned after save.
- GitHub tokens are not stored in plaintext; production GitHub integration must use short-lived installation tokens or encrypted credential storage.
- GitHub repository listing remains blocked until real credentials are supplied and verified; NOPE does not fake private repositories.
- AI prompts must avoid full secret values and unnecessary source dumps.
- AI action cache entries store redacted structured output and context metadata only; raw repository chunks and raw secrets are not persisted in the cache.

## Local AI service

- `nope-ai` is a reasoning service, not a sandbox.
- It receives focused evidence snippets, not whole repositories.
- Repository instructions, comments, README text, and source strings are treated as untrusted data inside prompts.
- Finding AI jobs are owner-scoped and have durable queued, running, completed, failed, and cancelled states.
- It has no shell or tool execution API through NOPE.
- The model directory is mounted read-only.
- Host secrets and the Docker socket are not mounted.
- The service runs without privileged mode and with dropped capabilities where practical.
- Model file paths are configured by deployment settings, not arbitrary user input.

## Rules v2 candidate boundaries

- Rules v2 treats scanner output and repository text as evidence, not truth.
- Weak candidates can be withheld or sent to manual review instead of becoming findings.
- Safe-pattern and contradictory evidence can reject candidates.
- Candidate APIs are owner-scoped through the scan owner check.
- Candidate snippets are redacted with the same secret redaction path used elsewhere in scan evidence.
- The current implementation is bounded by file count, file size, and candidate count limits so hostile repositories cannot force unlimited candidate generation.

## Failure safety

- Scanner failure marks scanner coverage as Failed.
- AI failure marks AI coverage as Failed or Partial.
- Build or sandbox failure preserves static findings and marks dynamic coverage incomplete.
- No failed check is converted into a passed security result.
