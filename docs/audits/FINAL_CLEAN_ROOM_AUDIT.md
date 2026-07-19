# Archived Clean-Room Audit

Reader note: this is an archived build log. It is intentionally blunt and checklist-heavy because I used it to keep the work honest while building, not because it is meant to be a polished product page.

The old clean-room audit was a giant verification ledger. It helped while I was checking migrations, Docker startup, scanner behavior, reports, Qwen, browser tests, and security boundaries. It also made the repo look like it was written by a checklist machine.

So this file now keeps the human version:

- Rebuild from scratch before trusting local behavior.
- Run the scanner-only benchmark before trusting scanner claims.
- Treat Qwen as optional reasoning, not as the source of truth.
- Keep GitHub private access clearly blocked until real credentials exist.
- Keep production-readiness claims separate from local-product claims.

The current commands are in [`../TESTING.md`](../TESTING.md), [`../DEPLOYMENT.md`](../DEPLOYMENT.md), and [`../../README.md`](../../README.md). The benchmark summaries are in [`../../examples/nope-benchmark`](../../examples/nope-benchmark).
