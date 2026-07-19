# NOPE Documentation

Current-facing docs live in this directory. Older build notes and audit ledgers live in [`audits/`](audits/) so the repo root stays focused.

## Start Here

| Document | Use it for |
| --- | --- |
| [`../README.md`](../README.md) | GitHub-facing overview, run commands, and true project state |
| [`CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md) | Current capability status and honest limits |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Service boundaries and system design |
| [`PIPELINE.md`](PIPELINE.md) | Scan flow, durable events, evidence gate, reports, drift |
| [`SECURITY_MODEL.md`](SECURITY_MODEL.md) | Threat model, safeguards, and residual risk |
| [`TRUST_AND_LIMITS.md`](TRUST_AND_LIMITS.md) | Fast reviewer guide to what is proven and what is not |
| [`SCANNERS.md`](SCANNERS.md) | Scanner adapters, parsing, evidence handling |
| [`SANDBOX.md`](SANDBOX.md) | Opt-in dynamic/ZAP scanning model |
| [`LOCAL_AI.md`](LOCAL_AI.md) | Qwen, llama.cpp, model mount, GPU/CPU profiles |
| [`TESTING.md`](TESTING.md) | Backend, frontend, benchmark, browser, and Docker checks |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | Common local setup and runtime issues |
| [`../examples/nope-benchmark`](../examples/nope-benchmark) | Small benchmark summaries for quick reviewer proof |

## Reference

| Document | Use it for |
| --- | --- |
| [`API_REFERENCE.md`](API_REFERENCE.md) | API routes and response contracts |
| [`DATABASE.md`](DATABASE.md) | Migrations and persistent entities |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Local deployment notes and production caveats |
| [`DEVELOPMENT.md`](DEVELOPMENT.md) | Contributor workflow |
| [`DESIGN_SYSTEM.md`](DESIGN_SYSTEM.md) | Frontend visual conventions |
| [`GITHUB_INTEGRATION.md`](GITHUB_INTEGRATION.md) | GitHub credential and repository contracts |
| [`OPERATIONS.md`](OPERATIONS.md) | Local health, logs, migrations, and cleanup |
| [`TECHNICAL_DEBT.md`](TECHNICAL_DEBT.md) | Remaining debt and explicit external blocks |
| [`FEATURE_STATUS.md`](FEATURE_STATUS.md) | Detailed feature-level status matrix |

## Older Notes

The files in [`audits/`](audits/) are useful when you need to trace how the project got here. For normal review, start with the README and capability matrix; they are much easier on the eyes.
