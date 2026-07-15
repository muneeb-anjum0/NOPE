# NOPE Benchmarks

Phase 12 adds a reproducible local benchmark fixture and a machine-readable runner.

## Fixture

- Fixture: `benchmarks/fixtures/nope-benchmark-v1`
- Manifest: `benchmarks/fixtures/nope-benchmark-v1/benchmark-manifest.json`
- Expected output: `benchmarks/expected/nope-benchmark-v1.expected.json`

The fixture intentionally covers hardcoded secrets, frontend secrets, SQL injection, NoSQL injection, command injection, XSS, unsafe HTML, SSRF, path traversal, file upload, IDOR, missing tenant scope, frontend-only authorization, insecure CORS, missing rate limit, AI cost abuse, vulnerable dependency, debug endpoint, public source map, unsafe Supabase RLS, public storage bucket, and tracker-before-consent.

## Commands

Scanner-only benchmark:

```powershell
$env:PYTHONPATH='apps/api'
python -m nope_api.benchmarks --mode scanner-only --output .nope-benchmark-results/scanner-only.json
```

Scanner-plus-Qwen benchmark:

```powershell
$env:PYTHONPATH='apps/api'
python -m nope_api.benchmarks --mode scanner-plus-qwen --output .nope-benchmark-results/scanner-plus-qwen.json
```

The same command works inside the API container:

```powershell
docker compose run --rm nope-api python -m nope_api.benchmarks --mode scanner-only --output /tmp/nope-benchmark-scanner-only.json
```

## Output

The JSON output includes:

- `expected_findings`
- `actual_findings`
- `true_positives`
- `false_positives`
- `known_false_negatives`
- `false_negatives`
- `scanner_source`
- `qwen_contribution`
- `duration_ms`
- `resource_use`
- `fix_verification`

Known false negatives are explicit expected items that the fixture contains but the current scanner set does not yet detect reliably. They keep benchmark gaps visible without falsely failing a reproducible run.

## Modes

- `scanner-only` disables AI by setting the local benchmark settings provider to `none`.
- `scanner-plus-qwen` leaves the configured Qwen provider active. If Qwen is unavailable, the benchmark records the AI review state honestly through `qwen_contribution`.

No external credentials are required.
