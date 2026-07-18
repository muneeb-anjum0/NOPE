# NOPE Scanners

NOPE treats scanner output as evidence. Scanner findings are normalized into the shared `Finding` model, scanner runs are persisted with command/exit-code/output metadata, and missing tools are reported as failed coverage instead of being faked.

## Bundled API Image Scanners

The API image installs:

- `semgrep` for multi-language static analysis.
- `gitleaks` for repository secret detection.
- `osv-scanner` for open-source dependency vulnerability checks.
- `trivy` for filesystem dependency/container/IaC checks.
- `checkov` for Terraform, Dockerfile, and CI/CD policy checks.
- `hadolint` for Dockerfile lint/security checks.
- `bandit` for Python security analysis.
- `OWASP ZAP baseline` is represented in the scanner contract. Static repository scans mark it skipped/not applicable, while Phase 10 sandbox scans can run it against a declared internal target.

These tools run during repository scans when applicable to the uploaded project.

Semgrep runs with the local NOPE ruleset at `security-packs/semgrep/nope.yml` so scans remain local-first and do not depend on Semgrep registry auto-configuration or metrics.

## Parser Coverage

Phase 2 parser support exists for:

- Semgrep JSON
- Gitleaks JSON
- OSV-Scanner JSON
- Trivy filesystem JSON
- Checkov JSON
- Hadolint JSON
- Bandit JSON
- OWASP ZAP baseline is not parsed during static repository scans because it is not applicable without a dynamic target. Phase 10 stores the bounded ZAP stdout/stderr evidence as sandbox artifacts.

Parsers produce normalized severity, confidence, category, affected file, line, evidence, remediation, source, and stable fingerprints.

## Execution Artifacts

Each scanner run records:

- Scanner name and version
- Status: `passed`, `failed`, or `skipped`
- Command arguments
- Exit code
- Redacted stdout and stderr, bounded by `NOPE_MAX_SCANNER_OUTPUT_BYTES`
- MinIO raw-output artifact reference when stdout/stderr exists
- Coverage categories
- Finding count

Secret-like values are redacted before raw output is stored in the scan snapshot, normalized scanner-run data, and MinIO artifact payload.

Raw scanner artifacts are JSON objects in `nope-artifacts` under `scans/{scan_id}/...`. The database links them through `uploaded_artifacts`, `job_artifacts`, and `scanner_runs.raw_artifact_id`.

## Capability Reporting

Authenticated users can call `GET /api/scanners/capabilities` to see:

- Installed status and health message
- Version string
- Coverage categories
- Supported file markers used for applicability checks

## Verified Smoke

- Docker API image: Semgrep `1.169.0`, Gitleaks `8.28.0`, OSV-Scanner `2.2.3`, Trivy `0.72.0`, Checkov `3.3.8`, Hadolint `2.14.0`, Bandit `1.9.4`.
- Repository fixture scan `scan_phase2_verify_20260715_zap_contract`: status `completed`, 29 findings total.
- Scanner findings in that smoke: Semgrep 1, Gitleaks 1, OSV-Scanner 5, Trivy 10, Checkov 6, Hadolint 2, Bandit 3, OWASP ZAP baseline 0 skipped/not applicable.
- MinIO artifacts were written for all seven external scanner raw outputs and linked from persisted scanner runs.

## Dynamic Sandbox Scanners

Repositories can opt into sandbox workflows with `.nope/sandbox.json`. The manifest can declare allowlisted build/test commands and an optional allowlisted startup command plus ZAP baseline scan. The socketless worker delegates execution to the internal `nope-runner`, which launches disposable Docker containers with read-only repository mounts, no sandbox Docker socket, no host home, no NOPE service secrets, CPU/memory/PID/tmpfs/log limits, no arbitrary mounts/env/networks, and network disabled for ordinary workflows. When ZAP is enabled, NOPE creates an internal Docker network, starts the app container, scans it from the ZAP container, records bounded evidence, and tears the network down.
