# NOPE Feature Ledger

This file is the quick version. It says what works today, what is still local-only, and where I would be careful before treating NOPE like production infrastructure.

The long phase-by-phase history is archived in [`audits/`](audits/). I keep it around because it is useful when tracing old decisions, but it should not be the first thing someone reads when they land in this repo.

## Working Locally

| Area | Where it stands | Notes |
| --- | --- | --- |
| Login and sessions | Working | Local accounts, sessions, and protected dashboard routes use Postgres-backed state. |
| Project folders | Working | Scans, baselines, drift, findings, assets, and reports stay scoped to the selected folder. |
| ZIP scans | Working | Uploads are bounded, extracted safely, and scanned through the worker pipeline. |
| URL checks | Working for authorized, non-destructive checks | Private/local targets are blocked unless explicitly allowed for the local sandbox path. |
| Queue and progress | Working | Redis moves jobs; Postgres keeps the durable event history. Browser refreshes do not erase scan progress. |
| Scanner pipeline | Working | NOPE rules, Semgrep, Gitleaks, OSV, Trivy, Checkov, Hadolint, Bandit, and ecosystem audit adapters are wired through controlled commands. |
| Rules v2 | Working with honest limits | 100+ validated catalog rules, candidate review, promotion gate, APIs, reports, and dashboard page are wired. Some families still use broad text/graph heuristics rather than full AST/dataflow parsing. |
| Evidence gate | Working | Weak rule hits are checked against nearby evidence before they become normal findings. This was added because noisy findings are worse than no findings. |
| Dynamic/ZAP path | Working for declared sandbox apps | Node/Python fixture workflows can run behind the runner boundary. Unsupported apps are reported plainly. |
| Findings lifecycle | Working | Findings keep stable fingerprints, evidence sources, lifecycle state, suppressions, recurrence, and reintroduction history. |
| Qwen actions | Working when the local model is mounted | Explain, Challenge, Fix, Test, and Patch Review run as durable jobs with a 24-hour cache. |
| RAG | Working without vector search | Retrieval is lexical, route-aware, symbol-aware, graph-aware, and finding-centered. It sends focused evidence, not whole repos. |
| Reports | Working | JSON, Markdown, SARIF, and PDF reports are generated from persisted scan data. |
| Drift and baselines | Working inside project folders | NOPE compares scans from the same folder so unrelated ZIPs do not create fake drift. |
| Browser tests | Working in CI fixture mode | Playwright covers core flows, accessibility checks, and visual snapshots. |
| GitHub connection flow | Locally implemented, externally blocked | Credential handling, callbacks, repository listing contracts, and fake-server tests exist. Real private access needs real credentials. |

## Still Not Magic

- NOPE does not prove an app is safe to ship.
- NOPE does not replace manual AppSec review.
- GitHub private repository activation needs real operator credentials.
- First uncached Qwen responses are limited by the local model and hardware.
- Authenticated browser crawling is not a general feature yet.
- The local Docker runner is intentionally narrow, but it is still a Docker-host risk if the runner itself is compromised.

## Where To Check The Details

| Need | File |
| --- | --- |
| Current truth table | [`CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md) |
| Pipeline behavior | [`PIPELINE.md`](PIPELINE.md) |
| Scanner behavior | [`SCANNERS.md`](SCANNERS.md) |
| Sandbox and ZAP model | [`SANDBOX.md`](SANDBOX.md) |
| Local Qwen setup | [`LOCAL_AI.md`](LOCAL_AI.md) |
| Security model | [`SECURITY_MODEL.md`](SECURITY_MODEL.md) |
| Benchmarks | [`BENCHMARKS.md`](BENCHMARKS.md) and [`../examples/nope-benchmark`](../examples/nope-benchmark) |

The short version: NOPE is useful today as a local security review workbench. It is not pretending to be a polished SaaS, and that is a deliberate line in the sand.
