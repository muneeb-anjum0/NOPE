# Rules v2 Implementation Plan

Pre-stage state:

- Branch: `main`
- Pre-stage commit: `4f1feb546b24db632a937581c1860316f9182f9d`
- Remote: `origin https://github.com/muneeb-anjum0/NOPE.git`
- Working tree at reconciliation start: clean
- First-party rule count: 35 rules in `security-packs/nope-core-rules.json`
- Scanner plugins: NOPE rules, Semgrep, Gitleaks, OSV-Scanner, Trivy, npm audit, pnpm audit, yarn audit, pip-audit, .NET package audit, cargo audit, govulncheck, composer audit, bundler-audit, Checkov, Hadolint, Bandit, OWASP ZAP baseline, and the built-in URL scanner
- Current rule path: `rules_engine.py` loads regex-style JSON rules and emits normal `Finding` objects.
- Current promotion path: `finding_validation.py` context-checks deduped findings into promoted, needs-context, or rejected decisions stored in scan stage data.
- Current persistence path: scan JSON snapshots plus normalized finding/evidence/scanner tables. There is no first-class candidate table before Stage 13.

## Current Rule Architecture

The current engine has two parts:

1. `rules_engine.run_rules(root)` scans text files with regex patterns from `nope-core-rules.json`.
2. `finding_validation.validate_findings(findings, root)` checks candidate findings before the dashboard receives promoted findings.

This already prevents some weak generated-output authorization findings from becoming normal findings, but it is not a first-class Rules v2 system. It lacks durable candidate records, rule metadata validation, rule-family coverage, candidate APIs, UI review surfaces, per-rule benchmark metrics, and explicit correlation paths.

## Current Rule Inventory

The 35 first-party rules cover secrets, authorization, CORS, Supabase, AI abuse, injection, rate limits, staging, privacy, authentication, CSRF, archive extraction, cookies, Docker, IaC, Firebase, build shell execution, and credential logging.

## Rules To Upgrade

- `NOPE-AUTHZ-001`: route/user ID to data access to missing owner/tenant proof.
- `NOPE-AUTHZ-002`: client-provided role/tenant only when it influences server-side access.
- `NOPE-SUPABASE-001`: service-role key correlated with client imports/public env/bundle paths.
- `NOPE-SUPABASE-002`: distinguish public data from weak authenticated policy and missing owner/tenant policy.
- `NOPE-SUPABASE-003`: public bucket correlated with private app usage.
- `NOPE-AI-001`: split evidence checks for auth, rate, budget, token caps, stream caps, tool allowlists, logging, uploads, retries, cancellation, and timeout.
- `NOPE-RATE-001`: expand to auth, signup, OTP, upload, export, report, AI, search, scrape, email, SMS, and PDF generation.
- `NOPE-CSRF-001`: framework-aware CSRF with bearer-token exceptions.
- `NOPE-COOKIE-001`: focus on auth/session cookies.
- `NOPE-HEADERS-001`: focused header evidence for CSP, HSTS, frame protection, referrer policy, permissions policy, MIME sniffing, and sensitive cache control.
- `NOPE-DOCKER-001`: final-stage runtime user, socket mounts, host mounts, capabilities, privileged mode, network mode, and security options.
- `NOPE-BUILD-001`: shell execution correlated with user, repository, package-script, CI, branch, filename, build-arg, and env inputs.

## Rules To Add

Rules v2 adds these families:

- Next.js authorization, data exposure, caching, redirects, errors, and uploads.
- Prisma/ORM lookup, mutation, relation, DTO, tenant, raw SQL, transaction, search, and soft-delete rules.
- Supabase/RLS table, policy, storage, signed URL, RPC, and anon-key rules.
- Auth-provider rules for Clerk, Auth.js, and Supabase Auth.
- Cross-source correlation rules for IDOR, mutation, RLS, storage, secret-to-client, cache, AI, export, webhook, admin, logging, redirect, upload, search, and background jobs.
- AI/cost-abuse rules for budgets, token caps, tool allowlists, logging, uploads, unauthenticated generation, prompt control, RAG trust boundaries, retry, timeout, and cancellation.
- Webhook/OAuth rules for signature verification, raw-body handling, replay, idempotency, OAuth state, redirect allowlists, token storage/logging, and provider mismatch.
- Rate-limit rules for expensive routes, upload/export/report quotas, auth abuse flows, search/scrape pagination, PDF generation, email/SMS, and GraphQL depth.
- Privacy rules for trackers, PII to third parties/AI, logs, error leakage, source maps, analytics identifiers, report redaction, and debug endpoints.
- Upload/archive/storage rules for MIME/size/extension/content checks, storage keys, executable paths, dangerous archive types, archive bombs, Unicode traversal, raw path downloads, signed URL auth/expiry, storage ACLs, and guessable IDs.
- Deployment/CI rules for debug mode, CORS credentials, CSP, HSTS, exposed admin/staging services, root containers, CI secret exposure, public data services, missing health/resource limits, and Docker socket mounts.

## Duplicate Or Overlapping Rules

Several rules intentionally overlap external scanners. The Stage 13 policy is:

- External findings remain valid even without NOPE correlation.
- NOPE correlation can merge multiple signals into one canonical finding.
- Related evidence is retained as contributing evidence, not inflated into duplicates.
- Weak NOPE-only candidates are withheld when required evidence is missing.

## Required Schema Changes

In the scan model:

- Add `rules_v2` summary data containing registered rules, candidates, promotion decisions, coverage, failures, and execution metrics.
- Preserve normal `Finding` objects for promoted findings.

Database migrations should eventually add normalized candidate and decision tables. For the first Stage 13 integration pass, scan JSON snapshot persistence is used so the feature survives restart without breaking current migrations or existing scan history.

## Required Graph Changes

Rules v2 needs reusable graph context:

- route to file
- file to database/storage/AI/shell/logging/cache risk
- route to auth and authorization signals
- finding to graph nodes and edges

The current lightweight graph supports route/file/database/auth-risk nodes. Rules v2 will add correlation paths in candidate decisions without requiring a full AST graph rewrite in the first integration pass.

## Required Persistence Changes

Minimum Stage 13 integration persistence:

- scan snapshot stores Rules v2 candidates, decisions, coverage, failures, and metrics
- reports read scan snapshot Rules v2 data
- APIs expose candidate and rule inventory from scan snapshot

Future normalized persistence:

- `rule_definitions`
- `rule_executions`
- `rule_candidates`
- `rule_candidate_evidence`
- `rule_promotion_decisions`
- `rule_benchmark_results`

## Required API Changes

- `GET /api/rules-v2/rules`
- `GET /api/scans/{scan_id}/rules-v2`
- `GET /api/scans/{scan_id}/rules-v2/candidates`
- `GET /api/scans/{scan_id}/rules-v2/candidates/{candidate_id}`

All routes must use existing authentication and scan ownership checks.

## Required Frontend Changes

Minimum UI:

- candidate review surface in the dashboard
- candidate filters by result, family, rule, severity, confidence, framework, and scanner
- candidate detail with evidence found, evidence missing, correlation path, rule metadata, and suggested manual verification
- rule coverage and execution health summary

Do not pollute the primary Findings table with withheld/rejected candidates.

## Required Benchmark Additions

- rule metadata validation
- candidate generation for representative vulnerable fixtures
- secure negative controls
- ambiguous wrapper withheld candidate
- external scanner correlation
- stable fingerprint and duplicate controls

Full per-rule fixture coverage for every future rule is required before claiming Stage 13 complete.

## Migration Strategy

Use scan JSON snapshot compatibility first, because Stage 1-12 scan history already depends on JSON snapshots. Add normalized candidate tables only when the API/UI contract stabilizes.

## Compatibility Strategy

- Preserve existing scans and findings.
- Preserve external scanner output.
- Preserve Stage 1-12 API routes.
- Do not change Qwen's authority; Qwen never promotes findings.
- Keep old `NOPE-AI-001` and other existing IDs as compatible aliases where evolved behavior is split into newer rules.

## Performance Risks

- Broad rules can create too many candidates.
- Graph traversal can explode if not bounded.
- Cross-file correlation can become slow on large repositories.

Controls:

- candidate count limits
- max file bytes
- max graph depth
- deterministic ordering
- per-family timing metrics
- failure isolation

## Stage Execution Order

1. Rule metadata schema and catalog.
2. Candidate and decision models.
3. Candidate generation from first-party findings, attack surface, code graph, repository files, and scanner findings.
4. Correlation and promotion gate.
5. Scan pipeline integration.
6. API exposure.
7. Report and documentation updates.
8. Tests and benchmark hooks.
9. Frontend candidate review.
10. Full verification, commit, and push.

