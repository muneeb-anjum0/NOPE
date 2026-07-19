# Withheld Candidates

Withheld candidates are suspicious signals that did not earn a normal finding.

They are not ignored. They are saved in normalized Rules v2 tables, mirrored in the scan snapshot for exports/backward compatibility, exposed through the Rules v2 APIs, visible in the Rules v2 dashboard page, and summarized in reports.

## Common Reasons

- owner or tenant predicate was not visible near a database lookup
- signature verification was not visible near webhook mutation
- rate limit or token budget was not visible near an AI endpoint
- storage policy looked risky but bucket intent was unclear
- a scanner finding existed but source-to-sink context was incomplete

## How To Use Them

Treat them as review work, not confirmed vulnerabilities. If a withheld candidate repeatedly appears in real projects, add a stronger detector, better safe-pattern recognition, or a benchmark fixture.

