# FEATURE STATUS

Date: 2026-07-18
Commit: `a46bbc5`

This root status file reflects the forensic audit state. Historical status material may exist under `docs/`; this file intentionally does not mark features complete based only on prior claims.

| Feature | Current status | Completion |
| --- | --- | ---: |
| Local Docker app startup with AI | Verified after base compose change | 90% |
| ZIP scan pipeline | Verified local E2E | 85% |
| PostgreSQL persistence | Verified migrations/tests/E2E | 85% |
| Redis worker | Works, events incomplete | 75% |
| Scanner execution | Real, benchmark failing | 64% |
| Evidence gate | Implemented, quality gaps remain | 74% |
| Qwen/llama.cpp | Live with 28 GPU layers under 5 GB | 78% |
| RAG | Real lexical/graph retrieval, no embeddings | 70% |
| Findings UI | Functional, not formally browser-tested | 78% |
| Attack map | Functional but heuristic | 70% |
| Reports | Verified JSON/MD/SARIF/PDF | 84% |
| Sandbox | Implemented but ordinary scans skip it; Docker socket risk | 60% |
| GitHub | Contracts only; real access blocked | 35% local / 0% activated |
| Benchmarks | Runner exists; current quality gate fails | 45% |
| Documentation | Audit refreshed, historical overclaims remain | 58% |

Current product classification: Functional MVP, not strong local beta yet, not production-ready.
