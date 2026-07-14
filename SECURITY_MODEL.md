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
- Docker sandbox execution is modeled with non-root, no Docker socket, memory/CPU/process limits, no host secrets, and network disabled by default.
- Target application containers and scanner containers are separated in the architecture.

## Secrets

- Logs are redacted with aggressive secret patterns.
- Findings display masked secret evidence, not full values.
- GitHub tokens are not stored in plaintext; production GitHub integration must use short-lived installation tokens or encrypted credential storage.
- AI prompts must avoid full secret values and unnecessary source dumps.

## Failure safety

- Scanner failure marks scanner coverage as Failed.
- AI failure marks AI coverage as Failed or Partial.
- Build or sandbox failure preserves static findings and marks dynamic coverage incomplete.
- No failed check is converted into a passed security result.
