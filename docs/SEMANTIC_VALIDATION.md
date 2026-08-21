# Semantic Security Validation (Stage 15.3)

Stage 15.3 extends the Stage 15.2 finding-quality gate. Scanner output and Rules v2 promotion decisions remain raw observations until the relevant vulnerability-family proof contract is satisfied.

## Deterministic facts

The semantic pass builds one repository snapshot per scan containing multi-label execution context, framework-resolved routes, source and sink signals, authentication and owner/tenant signals, effective deployment reachability, and data sensitivity. Unknown stays `UNKNOWN`.

Dockerfile `EXPOSE`, a container bind to `0.0.0.0`, a route-looking string, frontend fetch call, interface, schema, or security-sounding keyword is never public-runtime proof by itself. Qwen and vector similarity do not participate in promotion.

## Proof contracts

| Family | Required deterministic proof |
| --- | --- |
| Secret exposure | Sensitive source plus response/client/log/artifact/third-party sink. A non-placeholder hardcoded credential is independently actionable. |
| IDOR / authorization | Real server route, user/resource operation, and absence of effective authentication/ownership/tenant scope. |
| Debug/staging exposure | Real server route, runtime behavior, and public reachability. Loopback/container-only publishing rejects the public-exposure claim. |
| Information disclosure | Real server response path, meaningful data sensitivity, and reachability. Operational metadata is capped at low/informational. |
| Open redirect / command injection | Untrusted source and corresponding execution sink; incomplete flows are withheld. |
| Rate/AI cost controls | Real server route and relevant runtime behavior; a client call or keyword is insufficient. |
| Root container | Effective final runtime user after deployment overrides. |
| Dependency advisory | Runtime/deployment/privileged-CI scope from Stage 15.2. |

Findings store execution contexts, reachability, sensitivity, proof contract, proof steps, and negative evidence. The detail UI and reports explain why NOPE promoted or declined a signal. Raw, withheld, and rejected observations remain inspectable.

Scans and findings are persisted as versioned JSON payloads. New fields have conservative defaults, so historical scans remain readable and no relational migration is required. Normalized Rules v2 evidence tables remain unchanged.

`benchmarks/semantic-context` contains semantic-noise safe cases and vulnerable counterparts. It reports raw observations separately and measures promotion precision, recall, F1, and false-discovery rate.
