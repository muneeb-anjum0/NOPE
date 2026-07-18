# NOPE Security Model

NOPE treats every uploaded repository and every scanned target as potentially hostile.

## Authorization boundaries

- URL scans require explicit authorization confirmation.
- Approved hosts are derived from the requested target and optional scope settings.
- Redirects to unrelated domains are blocked.
- Private IP and localhost targets are blocked by default unless local sandbox scanning is explicitly enabled.
- Destructive testing is disabled by default.

## Upload boundaries

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

- The local `nope-runner` service still holds Docker daemon authority because local Docker sandboxing requires a daemon boundary. A runner compromise can become a Docker-host compromise. The important Stage 3 change is that the general worker, API, web app, scanner code, and uploaded repositories no longer receive unrestricted Docker daemon access.
- Rootless Docker, a Docker authorization proxy, or a separate runner host would further reduce this residual risk in production deployments.
- ZAP runs on a runner-created internal Docker network only when a repository explicitly opts in with a sandbox manifest.

## Secrets

- Logs are redacted with aggressive secret patterns.
- Findings display masked secret evidence, not full values.
- Test identity secrets, GitHub OAuth secrets, GitHub private keys, and webhook secrets are encrypted before persistence and are not returned after save.
- GitHub tokens are not stored in plaintext; production GitHub integration must use short-lived installation tokens or encrypted credential storage.
- GitHub repository listing remains blocked until real credentials are supplied and verified; NOPE does not fake private repositories.
- AI prompts must avoid full secret values and unnecessary source dumps.

## Local AI service

- `nope-ai` is a reasoning service, not a sandbox.
- It receives focused evidence snippets, not whole repositories.
- It has no shell or tool execution API through NOPE.
- The model directory is mounted read-only.
- Host secrets and the Docker socket are not mounted.
- The service runs without privileged mode and with dropped capabilities where practical.
- Model file paths are configured by deployment settings, not arbitrary user input.

## Failure safety

- Scanner failure marks scanner coverage as Failed.
- AI failure marks AI coverage as Failed or Partial.
- Build or sandbox failure preserves static findings and marks dynamic coverage incomplete.
- No failed check is converted into a passed security result.
