# NOPE Benchmark Example

Tiny note: this file is dry on purpose. It is here so a reviewer can check the numbers without opening a giant generated artifact.


This folder gives reviewers a quick, concrete artifact to inspect before running the whole stack.

The benchmark fixture lives in [`../../benchmarks/fixtures/nope-benchmark-v1`](../../benchmarks/fixtures/nope-benchmark-v1), and its expected findings live in [`../../benchmarks/expected/nope-benchmark-v1.expected.json`](../../benchmarks/expected/nope-benchmark-v1.expected.json).

The summaries here are intentionally small. The full benchmark command writes larger JSON/Markdown outputs to `.nope-benchmark-results/`, which is ignored because those files are generated artifacts.

## What This Proves

- NOPE can run a deterministic scanner-only benchmark without Qwen.
- The benchmark fixture currently covers 41 expected vulnerability categories.
- False positives and false negatives are counted explicitly.
- Duplicate/supporting scanner findings are separated from expected true positives.
- Qwen is optional; deterministic scanning remains meaningful when AI is not enabled.

## What This Does Not Prove

- It does not prove NOPE will catch every real-world vulnerability.
- It does not replace testing against real authorized repositories.
- It does not activate real GitHub private repository access.
- It does not prove production SaaS readiness.

## Reproduce It

```powershell
docker build -f docker/api.Dockerfile -t nope-api-benchmark .

docker run --rm `
  -v "${PWD}/.nope-benchmark-results:/app/.nope-benchmark-results" `
  nope-api-benchmark `
  python -m nope_api.benchmarks `
    --mode scanner-only `
    --output .nope-benchmark-results/scanner-only.json `
    --markdown-output .nope-benchmark-results/scanner-only.md
```

With a configured local Qwen model, use:

```powershell
docker run --rm `
  -v "${PWD}/.nope-benchmark-results:/app/.nope-benchmark-results" `
  nope-api-benchmark `
  python -m nope_api.benchmarks `
    --mode scanner-plus-qwen `
    --output .nope-benchmark-results/scanner-plus-qwen.json `
    --markdown-output .nope-benchmark-results/scanner-plus-qwen.md
```

## Included Summaries

| File | Purpose |
| --- | --- |
| [`scanner-only-summary.md`](scanner-only-summary.md) | Deterministic scanner benchmark result without Qwen |
| [`scanner-plus-qwen-summary.md`](scanner-plus-qwen-summary.md) | Benchmark result when local Qwen enrichment is available |
| [`expected-coverage.md`](expected-coverage.md) | Human-readable list of benchmark categories |
