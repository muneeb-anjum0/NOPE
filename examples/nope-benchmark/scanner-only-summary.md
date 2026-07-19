# Scanner-Only Benchmark Summary

Tiny note: this file is dry on purpose. It is here so a reviewer can check the numbers without opening a giant generated artifact.


Generated from `nope-benchmark-v1` using the local API scanner image.

| Metric | Value |
| --- | --- |
| Status | Passed |
| Expected fixtures | 41 |
| Actual findings | 79 |
| True positives | 41 |
| False positives | 0 |
| False negatives | 0 |
| Related duplicate/supporting findings | 40 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| Coverage | 80% |
| Qwen status | Not tested |

## Per Scanner

| Scanner | Findings |
| --- | ---: |
| NOPE rules | 41 |
| Trivy | 14 |
| OSV-Scanner | 9 |
| npm audit | 9 |
| Semgrep | 3 |
| Checkov | 3 |
| Bandit | 2 |
| Hadolint | 1 |

## Notes

- Scanner-only mode is the most important public proof path because it does not require a local model mount or GPU.
- The benchmark separates expected true positives from duplicate/supporting findings produced by additional scanners.
- Failed scanners: 0.
