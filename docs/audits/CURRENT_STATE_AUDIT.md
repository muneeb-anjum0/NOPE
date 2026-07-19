# Archived Current-State Audit

This audit was written when I needed to stop and ask, "what is actually real here?" That question was worth asking. The old version answered it with a wall of status text, which was accurate enough for development but not fun to read.

The current answer is cleaner:

- NOPE is a local security review workbench.
- The Docker stack runs web, API, worker, runner, Postgres, Redis, MinIO, and optional local Qwen.
- ZIP scans, scanner evidence, findings, reports, drift, baselines, and Qwen actions persist to durable state.
- GitHub private access is still externally blocked until real credentials are supplied.
- Production SaaS hardening is not done and should not be implied.

For the up-to-date version, read [`../CAPABILITY_MATRIX.md`](../CAPABILITY_MATRIX.md) and [`../TRUST_AND_LIMITS.md`](../TRUST_AND_LIMITS.md). Those files are where I want a reviewer to start.
