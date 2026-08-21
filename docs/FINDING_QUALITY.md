# Finding Quality and Promotion Gate v3

Stage 15.2 separates scanner evidence from NOPE's security conclusions. The governing rule is that external scanner output is evidence, not automatically a confirmed finding.

## Effective pipeline

```text
scanner raw artifact
  -> normalized raw observation
  -> canonical deduplication
  -> deterministic file/context validation
  -> scanner trust + rule classification
  -> dependency and effective-deployment correlation
  -> safe-pattern / compensating-control checks
  -> supersession
  -> Promotion Gate v3 disposition
  -> confirmed findings + inspectable non-confirmed observations
```

`Scan.raw_observations` preserves every normalized observation and its upstream scanner metadata. `Scan.findings` contains only `confirmed` and `confirmed_with_compensating_control` outcomes. Historical scan JSON remains readable because all Stage 15.2 fields have compatibility defaults; historical records are not rewritten.

## Dispositions

| Disposition | Meaning | Default UI treatment |
| --- | --- | --- |
| `confirmed` | Deterministic evidence proves an applicable security weakness | Actionable |
| `confirmed_with_compensating_control` | Weakness exists, but an explicit control reduces exposure | Actionable, control shown |
| `conditional` | Security relevance depends on unproven runtime/deployment conditions | Separate review view |
| `informational` | Security-related context that is not a deployed vulnerability | Separate review view |
| `withheld` | Suspicious but promotion evidence is insufficient | Advanced review |
| `rejected` | Non-security, contradicted, safe, duplicated, or superseded | Noise diagnostics |

Every outcome stores stable reason codes, a human explanation, security relevance, upstream severity, confidence, dependency scope, exposure, priority, actionability, deployment relevance, compensating controls, contradictory evidence, and supersession identity.

## Authority boundary

Rules v2 and deterministic NOPE logic are authoritative. Qwen and vector retrieval do not participate in disposition, severity, confidence, priority, reachability, or finding existence. They may explain a stored deterministic decision afterward.

## Scanner trust model

| Scanner | Initial meaning | Direct trust | Context required |
| --- | --- | --- | --- |
| NOPE rules / Rules v2 | Deterministic candidate | Rules v2 promotions and context-validated native rules | Safe-pattern contradiction still blocks |
| Semgrep | Security heuristic or framework rule | No blanket trust | Context/corroboration |
| Gitleaks | Secret-pattern signal | Strong signal, never secret content | Placeholder, fixture, generated, and example checks |
| OSV, Trivy, npm/pnpm/yarn audit | Real upstream advisory | Advisory existence only | Installed version, dependency scope, runtime/build/CI exposure |
| pip-audit, .NET, Cargo, govulncheck, Composer, Bundler | Real upstream advisory | Advisory existence only | Ecosystem scope/runtime evidence when available |
| Checkov | IaC/configuration signal | No blanket trust | Effective resource and deployment relevance |
| Hadolint | Mostly Docker best practice | `DL3002` receives security-specific handling | Effective runtime user; other unknown rules default to lint/noise |
| Bandit | Python security heuristic | No blanket trust | Context/corroboration |
| ZAP | Runtime/passive signal | Confirmed runtime behavior is stronger than passive headers | Deployment proxy and exposure context |
| NOPE URL scanner | Scoped runtime observation | Deterministic request evidence | Missing controls remain conditional where a proxy layer is unknown |

Unknown scanner rules fail conservatively into `withheld` unless an explicit scanner policy marks them as non-security noise. The maintainable registries live in `finding_quality.py` rather than scanner adapters.

## Dependency scope

JavaScript package manifests are resolved across workspaces into production, development, optional, and peer scopes. Undeclared lockfile packages are transitive when a manifest is available. A development advisory is informational by default, but remains confirmed when the package is imported by non-test runtime source or executes in build/CI context involving pull-request input, secrets, publishing, deployment, or install hooks. Upstream severity is preserved independently from NOPE priority.

Other ecosystems preserve advisories and use conservative `unknown`/`transitive` scope until deterministic manifest resolution is available; they are not silently promoted as deployed vulnerabilities.

## Effective deployment model

The resolver batches repository evidence and records provenance for Dockerfiles, Compose files, reverse proxies, ingress configuration, and Next.js configuration. Its current snapshot includes runtime user, healthcheck source, published ports, Docker socket mounts, privileged mode, read-only root filesystem, dropped capabilities, TLS termination, security headers, and CORS restriction evidence.

Implemented correlations include:

- Dockerfile healthcheck absence versus a Compose healthcheck.
- Image-level root user versus an explicit Compose non-root runtime override.
- Root-container promotion when no non-root effective override exists.

Unknown external infrastructure is never assumed.

## Deduplication and supersession

Canonical fingerprints merge package/CVE identities, code-flow identities, secret locations, and correlated source locations. Multiple scanner sources and evidence records are retained. Same-location, same-vulnerability-family confirmed observations are superseded by the stronger/more specific Rules v2 or better-corroborated result; the weaker observation remains in `raw_observations` with `REJECTED_SUPERSEDED`.

## Observability

`Scan.finding_quality` records raw observations, candidates, confirmed, conditional, informational, withheld, rejected, deduplicated, superseded, safe-pattern suppressed, dev-dependency downgraded, and compensating-control counts, plus per-scanner dispositions and the effective-deployment snapshot.

## Reports and UI

The default Findings view is Actionable. Conditional, Informational, Withheld, Rejected / Noise, and Raw Scanner Observations are separate views. Finding details explain the disposition, reason codes, priority, exposure, and compensating controls.

Executive JSON, Markdown, PDF, and ordinary Findings APIs use confirmed findings. Markdown includes non-confirmed diagnostic sections. SARIF preserves all raw observations and records NOPE disposition separately; non-confirmed observations use SARIF `note` level rather than being represented as NOPE vulnerabilities.

## Precision benchmark

`benchmarks/quality-corpora` contains vulnerable, safe, mixed, compensating-control, and dev-dependency adversarial corpora. A predicted positive is exactly an unsuperseded `confirmed` or `confirmed_with_compensating_control` observation. Metrics include precision, recall, F1, false-positive rate, and false-discovery rate. Informational outcomes remain part of the evaluated disposition set.

Known limitations are explicit: package reachability is evidence-based but not compiler-grade; non-JavaScript dependency scope is conservative; Compose correlation is repository-wide rather than a full profile/override interpreter; reverse-proxy parsing recognizes bounded controls but is not a general configuration evaluator.
