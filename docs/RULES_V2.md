# Rules v2

Rules v2 is NOPE's newer detection layer. It does not replace scanner output. It turns raw signals into candidates, checks surrounding context, then decides whether the evidence is strong enough to become a normal finding.

## What It Adds

- A versioned rule catalog with IDs, families, severity, evidence requirements, safe patterns, remediation, and benchmark references.
- Candidate records before findings exist.
- Correlation across repository text, attack-surface graph hints, and external scanner findings.
- Promotion-gate decisions: promoted, withheld, needs manual review, rejected, or not applicable.
- Report and API visibility into candidates that did not become findings.
- Normalized database persistence for candidates, evidence, correlations, promotion history, and candidate suppression state, with scan-snapshot fallback for old scans.
- A reusable repository context index for source blocks, imports, framework hints, auth/owner helpers, and Supabase RLS policy tables.

## Rule Families

- `legacy-upgraded`: the existing first-party NOPE rules lifted into the catalog.
- `nextjs`: route handlers, server actions, client/server data leaks, caching, redirects, uploads, and error leakage.
- `prisma`: ID lookups, mutations, tenant predicates, raw SQL, relation includes, and sensitive-field return paths.
- `supabase`: RLS, storage buckets, signed URLs, RPC, auth UID policy shape, and public table access.
- `auth-provider`: Clerk, Auth.js, and Supabase auth usage where identity is checked but not bound to data access.
- `correlation`: route-to-data, scanner-to-file, cache-to-auth, webhook-to-mutation, and secret-to-client paths.
- `ai-cost`: public AI endpoints, missing budgets, token caps, prompt control, and logging boundaries.
- `webhook-oauth`: signatures, replay protection, OAuth state, token storage, and unsafe return URLs.
- `rate-limit`: login, upload, export, AI, email/SMS, GraphQL, and expensive unauthenticated routes.
- `privacy`: trackers, logs, PII, third-party sharing, source maps, and client bundle leakage.
- `upload-storage`: archive, file type, storage key, public bucket, and executable upload paths.
- `deployment-ci`: Docker, CI secrets, privileged containers, headers, TLS, and build/script exposure.

## Current Boundary

Rules v2 is production-grade for NOPE's local scanner scope, but it is still bounded static analysis. It is not a full compiler or language server for every framework. The promotion gate stays conservative: weak candidates should show up as withheld or review items instead of polluting the normal Findings table.

