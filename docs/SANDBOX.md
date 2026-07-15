# NOPE Sandbox

Phase 10 adds a local Docker sandbox for repository workflows that need limited code execution. The sandbox is opt-in per repository through `.nope/sandbox.json`; repositories without a manifest are marked not applicable for dynamic sandbox coverage.

## Manifest

```json
{
  "version": 1,
  "workflows": [
    {
      "name": "python tests",
      "kind": "python",
      "command": "python -m pytest",
      "timeout_seconds": 60
    }
  ],
  "startup": {
    "command": "python -m http.server 8080 --bind 0.0.0.0",
    "port": 8080
  },
  "zap": {
    "enabled": true,
    "max_minutes": 1
  }
}
```

Supported initial workflow kinds are `node`, `python`, `static`, and `custom`. `node` and `static` default to the configured Node image, and `python` and `custom` default to the configured Python image. Images must match the configured allow-list prefixes.

## Isolation

Repository workflow containers are started with:

- Non-root user `65532:65532`.
- No privileged mode.
- `--security-opt no-new-privileges:true`.
- `--cap-drop ALL`.
- Network disabled by default with `--network none`.
- Read-only repository bind mount at `/workspace-src`.
- Writable tmpfs workspace at `/workspace`.
- Read-only root filesystem.
- Bounded CPU, memory, process, timeout, tmpfs, and log limits.
- `HOME=/tmp` and `NOPE_SANDBOX=1`.

Sandbox containers do not mount `/var/run/docker.sock`, host home directories, or NOPE service secrets.

## ZAP Flow

When `zap.enabled` is true, NOPE creates an internal Docker network, starts the declared application container on that network, runs `ghcr.io/zaproxy/zaproxy:stable` against `http://<app-container>:<port>`, records bounded stdout/stderr evidence, removes the app container, and removes the network.

The ZAP image uses a writable root filesystem because the upstream ZAP runtime writes startup files. It still uses dropped capabilities, `no-new-privileges`, private-network-only access, tmpfs work paths, and memory/PID/time limits. ZAP has its own bounded timeout because the baseline image can take longer than short build/test commands to initialize and write results.

## Docker Stack

The local Compose worker has Docker CLI and Docker socket access so it can orchestrate sibling sandbox containers. That access stays at the worker boundary and is not mounted into launched sandbox containers. The API exposes `GET /api/sandbox/health` for the configured limits and isolation flags.
