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
- Symlinks are rejected.
- Maximum archive size, extracted size, and file count are configurable.
- Temporary workspaces are isolated and cleaned up after scan completion.

## Execution boundaries

- Unknown application code is not executed by the API process.
- Repository sandbox workflows run in disposable Docker containers with non-root users, `no-new-privileges`, dropped capabilities, read-only repository mounts, read-only roots where supported, tmpfs work directories, memory/CPU/PID limits, bounded logs, and command timeouts.
- Sandbox workflow containers do not receive the Docker socket, host home, NOPE MinIO/Postgres/Redis/Qwen secrets, or privileged mode.
- Network is disabled by default for repository workflows.
- ZAP dynamic scans use a private internal Docker network: one constrained application container is started from the declared manifest, one ZAP container scans only that internal target, and both are removed after the run.
- The ZAP scanner image keeps its writable root filesystem because the upstream image writes runtime files during startup; it still receives dropped capabilities, `no-new-privileges`, private-network-only access, tmpfs work paths, and memory/PID/time limits.
- The worker is the Docker orchestrator in the local Compose stack. Its Docker socket access is not propagated into sandbox containers.
- Target application containers and scanner containers are separated in the architecture.

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
