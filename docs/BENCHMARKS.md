# NOPE Benchmarks

Benchmarks are where I try to keep myself honest. NOPE should not get to claim "it finds things" unless a small, reviewable fixture proves what it found, what it missed, and what it duplicated.

## Fixture

- Fixture: `benchmarks/fixtures/nope-benchmark-v1`
- Manifest: `benchmarks/fixtures/nope-benchmark-v1/benchmark-manifest.json`
- Expected output: `benchmarks/expected/nope-benchmark-v1.expected.json`

The fixture intentionally covers 41 security categories: backend and frontend secrets, committed `.env`, public source maps, SQL and NoSQL injection, command injection, stored/reflected XSS, unsafe HTML rendering, SSRF, path traversal, unsafe archive extraction, unsafe upload handling, IDOR, missing ownership and tenant scope, frontend-only authorization, authentication bypass, weak password reset, login brute force, signup abuse, OTP flooding, missing API rate limiting, AI cost abuse, insecure CORS, missing CSRF protection, vulnerable dependencies, unsafe Dockerfile, unsafe IaC, debug/staging exposure, missing and overly permissive Supabase RLS, public Supabase storage, permissive Firebase rules, tracker-before-consent, missing security headers, unsafe cookies, shell-command injection in build scripts, and credential leakage in logs/config.

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

Rules v2 has a separate focused regression lane in `apps/api/tests/test_stage13_rules_v2.py`. That lane checks catalog validation, promotion, withholding, scanner correlation, owner-scoped candidate APIs, report output, and deterministic candidate identity. It complements the benchmark fixture rather than replacing it.

## Current Local Result

Verified on 2026-07-19 from a rebuilt Stage 13 benchmark image:

| Mode | Status | Expected | Actual | TP | FP | FN | Known FN | Related duplicates | Precision | Recall | F1 | Duration |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| scanner-only | passed | 41 | 80 | 41 | 0 | 0 | 0 | 41 | 1.000 | 1.000 | 1.000 | 60.495s |
| scanner-plus-Qwen | passed | 41 | 70 | 41 | 0 | 0 | 0 | 31 | 1.000 | 1.000 | 1.000 | 99.575s |

The duplicate count represents related supporting evidence from multiple scanners, overlapping expected fixture concepts, or Rules v2 correlated evidence. It is not counted as a false positive when it is tied to a matched expected file/category.

## CI artifacts

`.github/workflows/benchmarks.yml` runs the scanner-only benchmark in the API scanner image on pushes and pull requests. It uploads `.nope-benchmark-results/scanner-only.json` and `.nope-benchmark-results/scanner-only.md` as the `scanner-only-benchmark` artifact.

The scanner-plus-Qwen benchmark stays local because GitHub runners do not have the GGUF model, NVIDIA GPU access, or the user-owned model mount.

## Modes

- `scanner-only` disables AI by setting the local benchmark settings provider to `none`.
- `scanner-plus-qwen` leaves the configured Qwen provider active. If Qwen is unavailable, the benchmark records the AI review state honestly through `qwen_contribution`.

No external credentials are required.
