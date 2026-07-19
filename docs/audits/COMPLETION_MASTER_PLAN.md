# Archived Build Plan

This file used to hold a very long stage-by-stage completion plan. It was useful while the project was moving fast, but it read terribly on GitHub. Too much ceremony, too many percentages, too much "acceptance criteria" energy.

I am keeping this short version instead:

- The old plan existed to keep implementation work ordered.
- The real current state now lives in [`../CAPABILITY_MATRIX.md`](../CAPABILITY_MATRIX.md).
- The readable feature overview lives in [`../FEATURE_STATUS.md`](../FEATURE_STATUS.md).
- The practical proof lives in [`../../examples/nope-benchmark`](../../examples/nope-benchmark).
- The details are still recoverable from git history if someone truly needs the old blow-by-blow record.

The important lesson from the old plan is simple: NOPE should not claim a feature is working unless it has a test, a command, or a running Docker path behind it.
