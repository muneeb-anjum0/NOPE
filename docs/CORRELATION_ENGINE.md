# Correlation Engine

The Rules v2 correlation engine connects signals that are weak alone but meaningful together.

## Inputs

- repository files under bounded scan limits
- existing findings from first-party and external scanners
- attack-surface routes, files, database access, authorization hints, and rate-limit hints
- scanner source metadata

## Outputs

- rule candidates with file, line, route, family, severity, confidence, evidence, and references
- decision records explaining why a candidate was promoted, withheld, rejected, or sent to manual review
- promoted findings only when evidence clears the gate

## Examples

- `route param -> Prisma findUnique -> no owner predicate` becomes an authorization candidate.
- `Gitleaks secret -> client/public path` becomes a correlated secret candidate.
- `webhook route -> mutation -> no signature evidence` becomes a webhook candidate.
- `auth route -> AI call -> no budget/rate/token controls` becomes an AI cost-abuse candidate.

The current implementation uses bounded lexical, route, scanner, and lightweight graph context. It is intentionally explainable; every candidate keeps the evidence and reason that caused it.

