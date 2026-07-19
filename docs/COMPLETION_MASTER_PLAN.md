# NOPE Completion Master Plan

The long-form audit trail lives in [`docs/audits/COMPLETION_MASTER_PLAN.md`](audits/COMPLETION_MASTER_PLAN.md). This file exists as the top-level stage tracker used by the stage completion prompts.

## Stage 13: Rules v2, Evidence Correlation, and Detection Intelligence

Pre-stage commit: `4f1feb546b24db632a937581c1860316f9182f9d`

Stage 13 adds a first-class Rules v2 layer between raw scanner/rule signals and promoted findings.

Implemented local scope:

- Rules v2 catalog schema with semantic versions, families, evidence requirements, promotion requirements, safe patterns, remediation, and tags.
- Existing NOPE rules upgraded into the catalog instead of being replaced.
- New framework-aware rule families for Next.js, Prisma, Supabase/RLS, auth providers, cross-evidence correlation, AI cost abuse, webhooks/OAuth, rate limits, privacy, uploads/storage, and deployment/CI.
- Candidate generation from repository text, attack-surface graph hints, and external scanner findings.
- Promotion decisions for `promoted`, `withheld`, `needs_manual_review`, and `rejected`.
- Rules v2 scan snapshot with candidates, decisions, coverage, metrics, failures, and promoted finding IDs.
- Owner-scoped API endpoints for rule inventory, Rules v2 scan summary, candidate lists, candidate filtering, and candidate detail.
- Report output for JSON, Markdown, SARIF, and PDF.
- Dashboard page for candidate review.
- Regression tests covering catalog validation, deterministic candidate identity, promotion, withholding, external scanner correlation, API authorization, pagination, and report output.

Known honest limit:

- Rules v2 is not a full AST/dataflow engine yet. It has real evidence correlation and promotion gating, but several catalog rules currently share broad text/graph heuristics instead of deep framework-specific parsers.
- Candidate records are durable through the scan JSON snapshot. Dedicated normalized database tables can be added in a future schema pass if candidate analytics need cross-scan querying without loading scan data.
