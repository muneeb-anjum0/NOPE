# Benchmark Expected Coverage

The `nope-benchmark-v1` fixture is intentionally small enough to audit, but broad enough to exercise the scanner pipeline.

It includes expected findings for:

- backend hardcoded secrets
- frontend exposed secrets
- committed `.env` exposure
- public source maps
- SQL injection
- NoSQL injection
- command injection
- stored XSS
- reflected XSS
- unsafe HTML rendering
- SSRF
- path traversal
- unsafe archive extraction
- unsafe file upload handling
- IDOR
- missing ownership checks
- missing tenant scope
- frontend-only authorization
- authentication bypass
- weak password reset
- login brute force exposure
- signup abuse
- OTP flooding
- missing API rate limiting
- AI cost abuse
- wildcard CORS
- missing CSRF protection
- vulnerable dependencies
- unsafe Dockerfile configuration
- unsafe IaC
- debug endpoint exposure
- staging exposure
- missing Supabase RLS
- overly permissive Supabase RLS
- public Supabase storage bucket
- permissive Firebase rules
- tracker-before-consent privacy risk
- missing security headers
- unsafe cookie configuration
- shell-command injection in build scripts
- credential leakage in logs/config

Safe negative controls are also included for scoped authorization, parameterized SQL, consent-gated tracking, and example-secret patterns.
