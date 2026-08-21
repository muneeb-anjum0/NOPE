# Correlation Engine

The Rules v2 correlation engine connects signals that are weak alone but meaningful together.

Stage 15.3 consumes deterministic correlation facts for proof but never treats vector similarity as evidence. Missing route, runtime, sink, authorization, or reachability facts remain unknown and cannot be synthesized by retrieval or Qwen.

## Inputs

- repository files under bounded scan limits
- existing findings from first-party and external scanners
- attack-surface routes, files, database access, authorization hints, and rate-limit hints
- scanner source metadata
- reusable repository context: source blocks, imports, framework hints, authorization helpers, owner/tenant guards, and Supabase owner-bound RLS policy tables

## Outputs

- rule candidates with file, line, route, family, severity, confidence, evidence, and references
- decision records explaining why a candidate was promoted, withheld, rejected, or sent to manual review
- promoted findings only when evidence clears the gate

## Examples

- `route param -> Prisma findUnique -> no owner predicate` becomes an authorization candidate.
- `Gitleaks secret -> client/public path` becomes a correlated secret candidate.
- `webhook route -> mutation -> no signature evidence` becomes a webhook candidate.
- `auth route -> AI call -> no budget/rate/token controls` becomes an AI cost-abuse candidate.

The current implementation is bounded and explainable. It does not try to be a full language server, but it does build a reusable context index before candidate generation so route handlers can be checked against helper functions, imported authorization wrappers, matching RLS policy files, source-block metadata, graph hints, and scanner evidence. Every candidate keeps the evidence and reason that caused it.
