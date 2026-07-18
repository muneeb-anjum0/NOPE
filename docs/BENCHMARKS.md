# NOPE Benchmarks

NOPE includes a reproducible local benchmark fixture and a machine-readable runner for scanner quality gates.

## Fixture

- Fixture: `benchmarks/fixtures/nope-benchmark-v1`
- Manifest: `benchmarks/fixtures/nope-benchmark-v1/benchmark-manifest.json`
- Expected output: `benchmarks/expected/nope-benchmark-v1.expected.json`

The fixture intentionally covers hardcoded secrets, frontend secrets, SQL injection, NoSQL injection, command injection, XSS, unsafe HTML, SSRF, path traversal, file upload, IDOR, missing tenant scope, frontend-only authorization, insecure CORS, missing rate limit, AI cost abuse, vulnerable dependency, debug endpoint, public source map, unsafe Supabase RLS, public storage bucket, and tracker-before-consent.

It also includes safe negative controls for parameterized SQL, correctly scoped authorization, consent-gated trackers, and placeholder/example secrets.

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

When the stack is already running, use `exec`:

```powershell
docker compose exec -T nope-api python -m nope_api.benchmarks --mode scanner-only --output /tmp/nope-benchmark-scanner-only.json
docker compose exec -T nope-api python -m nope_api.benchmarks --mode scanner-plus-qwen --output /tmp/nope-benchmark-scanner-plus-qwen.json
```

## Output

The JSON output includes:

- `expected_findings`
- `actual_findings`
- `true_positives`
- `false_positives`
- `known_false_negatives`
- `false_negatives`
- `duplicate_count`
- `precision`
- `recall`
- `f1`
- `scanner_source`
- `qwen_contribution`
- `duration_ms`
- `resource_use`
- `fix_verification`

The runner also writes a Markdown summary next to the JSON output unless `--markdown-output` is set explicitly.

Known false negatives are no longer accepted as a passing state. If any expected item is missing, scanner-only and scanner-plus-Qwen modes fail.

## Current verified Stage 1 result

Verified on 2026-07-18 from the canonical Docker stack after rebuilding:

| Mode | Status | Expected | Actual | TP | FP | FN | Known FN | Related duplicates | Precision | Recall | F1 | Duration |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| scanner-only | passed | 22 | 43 | 22 | 0 | 0 | 0 | 22 | 1.000 | 1.000 | 1.000 | 37.044s |
| scanner-plus-Qwen | passed | 22 | 43 | 22 | 0 | 0 | 0 | 22 | 1.000 | 1.000 | 1.000 | 76.587s |

The duplicate count represents related supporting evidence from multiple scanners or overlapping expected fixture concepts. It is not counted as a false positive when it is tied to a matched expected file/category.

## Modes

- `scanner-only` disables AI by setting the local benchmark settings provider to `none`.
- `scanner-plus-qwen` leaves the configured Qwen provider active. If Qwen is unavailable, the benchmark records the AI review state honestly through `qwen_contribution`.

No external credentials are required.
