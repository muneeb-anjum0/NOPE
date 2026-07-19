# Promotion Gate

The promotion gate is the line between suspicious evidence and an actual finding.

## Decisions

- `promoted`: enough deterministic or strongly correlated evidence exists and no safe pattern contradicts it.
- `withheld`: suspicious evidence exists, but required proof is missing.
- `needs_manual_review`: evidence is mostly inferred and should not become a finding automatically.
- `rejected`: safe-pattern or contradictory evidence lowered confidence below the threshold.
- `not_applicable`: reserved for rule applicability checks.

## Why This Matters

Old heuristic-only findings can feel noisy. Rules v2 keeps weak matches visible without pretending they are confirmed. That is the whole point: fewer false "critical" findings, more honest evidence.

## What Gets Stored

Each decision stores:

- candidate ID
- rule ID and version
- result
- evidence used
- missing and contradictory evidence
- confidence and evidence strength
- human-readable reason
- machine reason
- correlation path
- suggested manual verification where useful
