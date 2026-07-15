# NOPE Scanners

NOPE treats scanner output as evidence. Scanner findings are normalized into the shared `Finding` model, scanner runs are persisted with command/exit-code/output metadata, and missing tools are reported as failed coverage instead of being faked.

## Bundled API Image Scanners

The API image installs:

- `semgrep` for multi-language static analysis.
- `bandit` for Python security analysis.

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

Parsers produce normalized severity, confidence, category, affected file, line, evidence, remediation, source, and stable fingerprints.

## Execution Artifacts

Each scanner run records:

- Scanner name and version placeholder
- Status: `passed`, `failed`, or `skipped`
- Command arguments
- Exit code
- Redacted stdout and stderr, bounded by `NOPE_MAX_SCANNER_OUTPUT_BYTES`
- Coverage categories
- Finding count

Secret-like values are redacted before raw output is stored in the scan snapshot and normalized scanner-run data.

## Remaining Phase 2 Work

- Add containerized execution for Gitleaks, OSV-Scanner, Trivy, Checkov, and Hadolint.
- Persist raw scanner artifacts to MinIO with authorized downloads.
- Add scanner capability/version endpoint.
- Add scanner image availability checks.
- Add broader vulnerable fixtures for parser and integration tests.

## Verified Smoke

- Docker API image: Semgrep `1.169.0`, Bandit `1.9.4`.
- Repository ZIP scan `scan_28e96fc09a904bc9`: Semgrep status `passed`, exit code `1`, 2 normalized findings, redacted raw output captured.
