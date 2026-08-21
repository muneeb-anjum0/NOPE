# Archived Implementation Worklog

## Stage 15.3 — Semantic Security Validation

- Baseline SHA: `825e3a130b333edb0cdab261eb9947b68330dfa4`.
- Preserved Stage 15.2 raw observations, dispositions, scanner trust, dependency/deployment correlation, supersession, reports, and UI filters.
- Added deterministic context, source/sink, route, reachability, sensitivity, negative-evidence, and family-proof evaluation to the normal gate.
- Added paired semantic corpus and evidence-chain UI/report fields. No Stage 16 work was started.

This used to be the running diary of the build. It had value at the time: every scanner, UI pass, Docker refresh, Qwen fix, report change, and pipeline hardening step had somewhere to land.

But a giant worklog is not a good first impression. It makes the repo feel noisier than the product actually is.

The useful parts have been folded into:

- [`../PIPELINE.md`](../PIPELINE.md)
- [`../SCANNERS.md`](../SCANNERS.md)
- [`../SECURITY_MODEL.md`](../SECURITY_MODEL.md)
- [`../LOCAL_AI.md`](../LOCAL_AI.md)
- [`../TECHNICAL_DEBT.md`](../TECHNICAL_DEBT.md)

Git history is still the best place to inspect exactly when something changed. This file is now just a signpost.
