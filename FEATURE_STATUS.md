# FEATURE STATUS

Date: 2026-07-18
Commit: `f0098bb` plus Stage 1 working tree changes

This root status file reflects the forensic audit state. Historical status material may exist under `docs/`; this file intentionally does not mark features complete based only on prior claims.

| Feature | Current status | Completion |
| --- | --- | ---: |
| Local Docker app startup with AI | Verified after base compose change | 90% |
| ZIP scan pipeline | Verified local E2E | 85% |
| PostgreSQL persistence | Verified migrations/tests/E2E | 85% |
| Redis worker | Works, events incomplete | 75% |
| Scanner execution | Real Docker benchmark gates pass for scanner-only and scanner-plus-Qwen | 82% |
| Evidence gate | Improved benchmark validation and auth context promotion; broader quality work remains | 78% |
| Qwen/llama.cpp | Live with 28 GPU layers under 5 GB | 78% |
| RAG | Real lexical/graph retrieval, no embeddings | 70% |
| Findings UI | Functional, not formally browser-tested | 78% |
| Attack map | Functional but heuristic | 70% |
| Reports | Verified JSON/MD/SARIF/PDF | 84% |
| Sandbox | Implemented but ordinary scans skip it; Docker socket risk | 60% |
| GitHub | Contracts only; real access blocked | 35% local / 0% activated |
| Benchmarks | Stage 1 benchmark gate verified passing in Docker | 90% |
| Documentation | Audit refreshed, historical overclaims remain | 58% |

Current product classification: Functional MVP moving toward strong local beta, not production-ready. Stage 1 benchmark correctness is complete; Stage 2 durable events/progress remains next.
