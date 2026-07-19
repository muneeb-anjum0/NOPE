# Trust and Limits

NOPE is strongest when it is judged as a local security-review workbench, not as a production SaaS or a magic proof of safety.

## What Is Concrete Today

- The scanner-only benchmark runs in Docker and produces machine-readable metrics.
- The benchmark fixture has 41 expected findings plus safe negative controls.
- Browser E2E, accessibility, and visual regression tests run in GitHub Actions.
- Scan events, findings, reports, baselines, drift, and AI actions are stored durably.
- The general worker is socketless; sandbox Docker access is narrowed to `nope-runner`.
- Qwen actions are optional and use focused evidence, not raw whole-repository prompts.

## What I Would Not Overclaim

- NOPE does not guarantee an application is secure.
- NOPE does not replace manual AppSec review.
- NOPE does not currently provide production SaaS deployment hardening.
- GitHub private repository activation is blocked until real credentials and installations are configured.
- Authenticated dynamic crawling is future scope; current dynamic scanning is manifest-declared and intentionally constrained.
- First uncached local-Qwen responses are limited by the configured model and hardware.

## Why Some Things Are Narrow On Purpose

The sandbox and URL scanner are conservative because NOPE processes hostile repositories and user-supplied targets. A broad dynamic scanner that can run arbitrary commands, mount arbitrary paths, or crawl arbitrary private networks would be more impressive at first glance and much harder to trust.

The current design favors evidence, explicit skipped/failed states, and bounded execution over pretending every scan mode is always available.

## How To Review This Repo Quickly

1. Read [`../examples/nope-benchmark/scanner-only-summary.md`](../examples/nope-benchmark/scanner-only-summary.md).
2. Check [`CAPABILITY_MATRIX.md`](CAPABILITY_MATRIX.md) for the true capability/limit table.
3. Run the scanner-only benchmark from [`../examples/nope-benchmark/README.md`](../examples/nope-benchmark/README.md).
4. Inspect [`SECURITY_MODEL.md`](SECURITY_MODEL.md) for residual risk.
5. Inspect GitHub Actions for the benchmark and browser E2E checks.
