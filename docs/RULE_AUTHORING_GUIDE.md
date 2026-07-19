# Rule Authoring Guide

Rules v2 rules live in code for now, inside `apps/api/nope_api/rules_v2.py`. The catalog is validated at runtime and in tests.

## Required Rule Shape

Every rule needs:

- stable ID like `NOPE-PRISMA-001`
- semantic version like `2.0.0`
- title and description
- family and category
- default severity
- evidence requirements
- correlation requirements
- promotion requirements
- rejection conditions
- safe patterns
- remediation

## Good Rule Design

A strong NOPE rule should say:

- what source creates suspicion
- what sink or risky behavior matters
- what context must be present before promotion
- what safe pattern can reject the candidate
- what evidence should appear in reports
- what fixture proves it works

Avoid rules that only match a scary word. Those belong in candidate review, not confirmed findings.

## Adding a Rule

1. Add the metadata in `_catalog_rules()`.
2. Add candidate generation in `_file_candidates()`, `_surface_candidates()`, or `_scanner_candidates()`.
3. Give the candidate direct evidence, missing evidence, safe-pattern evidence, or correlation references.
4. Add a unit test with both vulnerable and safe examples.
5. Run the Stage 13 test suite and the benchmark suite.

