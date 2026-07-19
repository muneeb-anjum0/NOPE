# Rule Benchmarks

Rules v2 benchmark coverage starts with targeted tests and the existing scanner-only benchmark.

Current Stage 13 checks:

- catalog validation and rule count
- conclusive secret promotion
- weak authorization withholding
- external scanner correlation
- candidate API authorization and pagination
- deterministic candidate identity
- report output for JSON, Markdown, SARIF, and PDF

The scanner-only benchmark remains the quick precision/recall proof for the existing fixture set. Rules v2 should improve evidence quality without breaking that baseline.

Useful commands:

```powershell
python -m pytest apps/api/tests/test_stage13_rules_v2.py -vv --tb=short
python -m pytest apps/api/tests/test_phase13_expansion.py apps/api/tests/test_stage13_rules_v2.py -vv --tb=short
docker build -f docker/api.Dockerfile -t nope-api-benchmark .
docker run --rm -v "${PWD}/.nope-benchmark-results:/app/.nope-benchmark-results" nope-api-benchmark python -m nope_api.benchmarks --mode scanner-only --output .nope-benchmark-results/scanner-only.json --markdown-output .nope-benchmark-results/scanner-only.md
```

