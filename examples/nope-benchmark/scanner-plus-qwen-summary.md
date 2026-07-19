# Scanner-Plus-Qwen Benchmark Summary

Generated from `nope-benchmark-v1` with local Qwen enrichment available.

| Metric | Value |
| --- | --- |
| Status | Passed |
| Expected fixtures | 41 |
| Actual findings | 70 |
| True positives | 41 |
| False positives | 0 |
| False negatives | 0 |
| Related duplicate/supporting findings | 31 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| Coverage | 83% |
| Qwen status | Complete |

## Per Scanner

| Scanner | Findings |
| --- | ---: |
| NOPE rules | 41 |
| Trivy | 14 |
| OSV-Scanner | 9 |
| Semgrep | 3 |
| Checkov | 3 |
| Bandit | 2 |
| Hadolint | 1 |

## Notes

- Qwen is not the scanner engine. It enriches selected evidence after deterministic findings exist.
- Deterministic scan success is preserved if Qwen is unavailable or fails.
- First uncached AI responses are still hardware-bound.
