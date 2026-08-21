from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Iterable

from nope_api.models import (
    Confidence,
    DependencyScope,
    Exposure,
    Finding,
    FindingDisposition,
    FindingPriority,
    SecurityRelevance,
)
from nope_api.rules_engine import dedupe_findings
from nope_api.semantic_validation import build_semantic_context, evaluate_semantic_finding


@dataclass(frozen=True)
class ScannerTrustProfile:
    scanner: str
    default_relevance: SecurityRelevance
    requires_corroboration: bool = True
    runtime_relevance_required: bool = False
    unknown_rule_disposition: FindingDisposition = FindingDisposition.withheld


@dataclass(frozen=True)
class ScannerRuleClassification:
    scanner: str
    rule_pattern: str
    relevance: SecurityRelevance
    default_disposition: FindingDisposition
    reason_code: str
    requires_corroboration: bool = True
    runtime_relevance_required: bool = False
    noise_class: str | None = None
    superseded_by: tuple[str, ...] = ()


SCANNER_TRUST_REGISTRY: dict[str, ScannerTrustProfile] = {
    "nope rules": ScannerTrustProfile("NOPE rules", SecurityRelevance.direct_security_vulnerability, False),
    "nope rules v2": ScannerTrustProfile("NOPE Rules v2", SecurityRelevance.direct_security_vulnerability, False),
    "semgrep": ScannerTrustProfile("Semgrep", SecurityRelevance.direct_security_vulnerability),
    "gitleaks": ScannerTrustProfile("Gitleaks", SecurityRelevance.direct_security_vulnerability, False),
    "osv-scanner": ScannerTrustProfile("OSV-Scanner", SecurityRelevance.dependency_advisory, False, True),
    "trivy": ScannerTrustProfile("Trivy", SecurityRelevance.dependency_advisory, False, True),
    "npm audit": ScannerTrustProfile("npm audit", SecurityRelevance.dependency_advisory, False, True),
    "pnpm audit": ScannerTrustProfile("pnpm audit", SecurityRelevance.dependency_advisory, False, True),
    "yarn audit": ScannerTrustProfile("yarn audit", SecurityRelevance.dependency_advisory, False, True),
    "pip-audit": ScannerTrustProfile("pip-audit", SecurityRelevance.dependency_advisory, False, True),
    ".net package audit": ScannerTrustProfile(".NET package audit", SecurityRelevance.dependency_advisory, False, True),
    "cargo audit": ScannerTrustProfile("cargo audit", SecurityRelevance.dependency_advisory, False, True),
    "govulncheck": ScannerTrustProfile("govulncheck", SecurityRelevance.dependency_advisory, False, True),
    "composer audit": ScannerTrustProfile("composer audit", SecurityRelevance.dependency_advisory, False, True),
    "bundler-audit": ScannerTrustProfile("bundler-audit", SecurityRelevance.dependency_advisory, False, True),
    "checkov": ScannerTrustProfile("Checkov", SecurityRelevance.configuration_weakness, True, True),
    "hadolint": ScannerTrustProfile("Hadolint", SecurityRelevance.style_lint, True, True, FindingDisposition.rejected),
    "bandit": ScannerTrustProfile("Bandit", SecurityRelevance.direct_security_vulnerability, True),
    "owasp zap": ScannerTrustProfile("OWASP ZAP", SecurityRelevance.configuration_weakness, True, True),
    "zap baseline": ScannerTrustProfile("ZAP baseline", SecurityRelevance.configuration_weakness, True, True),
    "nope url scanner": ScannerTrustProfile("NOPE URL scanner", SecurityRelevance.configuration_weakness, False, True),
    "nope sandbox": ScannerTrustProfile("NOPE sandbox", SecurityRelevance.direct_security_vulnerability, True, True),
}

SCANNER_RULE_CLASSIFICATION_REGISTRY: tuple[ScannerRuleClassification, ...] = (
    ScannerRuleClassification("Hadolint", r"^DL3002$", SecurityRelevance.deployment_hardening, FindingDisposition.conditional, "CONDITIONAL_EFFECTIVE_RUNTIME_USER", False, True),
    ScannerRuleClassification("Hadolint", r"HEALTH", SecurityRelevance.deployment_hardening, FindingDisposition.conditional, "CONDITIONAL_DEPLOYMENT_UNKNOWN", True, True),
    ScannerRuleClassification("Hadolint", r".*", SecurityRelevance.style_lint, FindingDisposition.rejected, "REJECTED_NON_SECURITY_LINT", True, False, "docker_best_practice"),
    ScannerRuleClassification("Gitleaks", r".*", SecurityRelevance.direct_security_vulnerability, FindingDisposition.conditional, "CONDITIONAL_SECRET_VALIDITY", False),
    ScannerRuleClassification("OSV-Scanner", r".*", SecurityRelevance.dependency_advisory, FindingDisposition.conditional, "CONDITIONAL_DEPENDENCY_SCOPE_UNKNOWN", False, True),
    ScannerRuleClassification("Trivy", r".*", SecurityRelevance.dependency_advisory, FindingDisposition.conditional, "CONDITIONAL_DEPENDENCY_SCOPE_UNKNOWN", False, True),
    ScannerRuleClassification("Checkov", r".*", SecurityRelevance.configuration_weakness, FindingDisposition.conditional, "CONDITIONAL_DEPLOYMENT_UNKNOWN", True, True),
    ScannerRuleClassification("OWASP ZAP", r".*(?:header|cookie|cache).*", SecurityRelevance.security_hardening, FindingDisposition.conditional, "CONDITIONAL_DEPLOYMENT_UNKNOWN", True, True, "passive_hardening"),
    ScannerRuleClassification("Semgrep", r".*", SecurityRelevance.direct_security_vulnerability, FindingDisposition.withheld, "WITHHELD_SCANNER_CORROBORATION_REQUIRED", True),
    ScannerRuleClassification("Bandit", r".*", SecurityRelevance.direct_security_vulnerability, FindingDisposition.withheld, "WITHHELD_SCANNER_CORROBORATION_REQUIRED", True),
)

NON_SECURITY_TERMS = {
    "style": SecurityRelevance.style_lint,
    "format": SecurityRelevance.style_lint,
    "maintain": SecurityRelevance.maintainability,
    "performance": SecurityRelevance.performance,
    "reliability": SecurityRelevance.reliability,
    "best practice": SecurityRelevance.code_quality,
    "deprecated": SecurityRelevance.maintainability,
}
SECURITY_TERMS = (
    "auth", "secret", "injection", "xss", "csrf", "cors", "ssrf", "traversal",
    "redirect", "credential", "crypt", "permission", "privilege", "exposure", "cve",
    "vulnerab", "rls", "webhook", "upload", "cookie", "header", "tls", "root",
)
PLACEHOLDER_RE = re.compile(r"(?i)\b(example|sample|fixture|dummy|fake|test|changeme|replace[-_ ]?me|xxxx+)\b")
CI_PATH_RE = re.compile(r"(^|/)(\.github/workflows|\.gitlab-ci|azure-pipelines|Jenkinsfile|buildkite)(/|$)", re.I)
HEALTHCHECK_RE = re.compile(r"\bhealthcheck\b", re.I)
ROOT_USER_RE = re.compile(r"(?im)^\s*USER\s+(root|0)(?:\s|$)")
NON_ROOT_USER_RE = re.compile(r"(?im)^\s*USER\s+(?!root(?:\s|$)|0(?:\s|$))\S+")
COMPOSE_NON_ROOT_RE = re.compile(r"(?im)^\s*user\s*:\s*['\"]?(?!root(?:['\"]|\s|$)|0(?::0)?(?:['\"]|\s|$))[^\s#]+")


@dataclass
class EffectiveDeploymentContext:
    dockerfiles: list[str] = field(default_factory=list)
    compose_files: list[str] = field(default_factory=list)
    dockerfile_healthcheck: bool = False
    compose_healthcheck: bool = False
    dockerfile_root: bool = False
    dockerfile_non_root: bool = False
    compose_non_root: bool = False
    published_ports: list[str] = field(default_factory=list)
    docker_socket_mounted: bool = False
    privileged: bool = False
    read_only_root: bool = False
    cap_drop_all: bool = False
    tls_termination: bool = False
    security_headers: list[str] = field(default_factory=list)
    cors_restriction: bool = False
    provenance: list[str] = field(default_factory=list)


@dataclass
class DependencyContext:
    scopes: dict[str, set[DependencyScope]] = field(default_factory=lambda: defaultdict(set))
    ci_text: str = ""
    scripts_text: str = ""
    runtime_text: str = ""


def scanner_trust_profile(scanner: str | None) -> ScannerTrustProfile:
    normalized = (scanner or "").strip().lower()
    if normalized in SCANNER_TRUST_REGISTRY:
        return SCANNER_TRUST_REGISTRY[normalized]
    for key, profile in SCANNER_TRUST_REGISTRY.items():
        if key in normalized:
            return profile
    return ScannerTrustProfile(scanner or "unknown", SecurityRelevance.unknown)


def scanner_rule_classification(scanner: str | None, rule_id: str | None) -> ScannerRuleClassification | None:
    scanner_name = (scanner or "").lower()
    rule = rule_id or ""
    for classification in SCANNER_RULE_CLASSIFICATION_REGISTRY:
        if classification.scanner.lower() in scanner_name and re.search(classification.rule_pattern, rule, re.I):
            return classification
    return None


def resolve_effective_deployment(root: Path | None) -> EffectiveDeploymentContext:
    context = EffectiveDeploymentContext()
    if not root or not root.exists():
        return context
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", "node_modules", ".next", "dist", "build"} for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        lowered = path.name.lower()
        if lowered == "dockerfile" or lowered.startswith("dockerfile.") or lowered.endswith(".dockerfile"):
            text = _read(path)
            context.dockerfiles.append(rel)
            context.dockerfile_healthcheck |= bool(re.search(r"(?im)^\s*HEALTHCHECK\b", text))
            context.dockerfile_root |= bool(ROOT_USER_RE.search(text)) or not bool(NON_ROOT_USER_RE.search(text))
            context.dockerfile_non_root |= bool(NON_ROOT_USER_RE.search(text))
            context.provenance.append(f"Dockerfile context: {rel}")
        elif lowered in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"} or lowered.startswith("docker-compose."):
            text = _read(path)
            context.compose_files.append(rel)
            context.compose_healthcheck |= bool(HEALTHCHECK_RE.search(text))
            context.compose_non_root |= bool(COMPOSE_NON_ROOT_RE.search(text))
            context.published_ports.extend(re.findall(r"(?m)^\s*-\s*['\"]?([^\s#]+:[^\s#]+)['\"]?\s*$", text))
            context.docker_socket_mounted |= "/var/run/docker.sock" in text
            context.privileged |= bool(re.search(r"(?im)^\s*privileged\s*:\s*true", text))
            context.read_only_root |= bool(re.search(r"(?im)^\s*read_only\s*:\s*true", text))
            context.cap_drop_all |= bool(re.search(r"(?is)cap_drop\s*:\s*(?:\n\s*-\s*ALL|\[\s*['\"]?ALL)", text))
            context.provenance.append(f"Compose context: {rel}")
        elif lowered in {"nginx.conf", "caddyfile", "traefik.yml", "traefik.yaml"} or "ingress" in lowered:
            text = _read(path)
            context.tls_termination |= bool(re.search(r"(?i)listen\s+443|ssl_certificate|tls\s|websecure|certresolver", text))
            for header in ("content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"):
                if header in text.lower():
                    context.security_headers.append(f"{header} ({rel})")
        elif lowered in {"next.config.js", "next.config.mjs", "next.config.ts"}:
            text = _read(path)
            context.cors_restriction |= "access-control-allow-origin" in text.lower() and "*" not in text
    return context


def resolve_dependency_context(root: Path | None) -> DependencyContext:
    context = DependencyContext()
    if not root or not root.exists():
        return context
    runtime_chunks: list[str] = []
    ci_chunks: list[str] = []
    scripts: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", "node_modules", ".next", "dist", "build"} for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        if path.name == "package.json":
            try:
                payload = json.loads(_read(path))
            except json.JSONDecodeError:
                continue
            for section, scope in (
                ("dependencies", DependencyScope.production),
                ("devDependencies", DependencyScope.development),
                ("optionalDependencies", DependencyScope.optional),
                ("peerDependencies", DependencyScope.peer),
            ):
                for package in (payload.get(section) or {}):
                    context.scopes[package.lower()].add(scope)
            scripts.append(json.dumps(payload.get("scripts") or {}, sort_keys=True))
            continue
        if path.stat().st_size > 256 * 1024:
            continue
        text = _read(path)
        if CI_PATH_RE.search(rel):
            ci_chunks.append(text)
        elif path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".php", ".cs", ".rs"} and not re.search(r"(^|/)(test|tests|__tests__|spec|examples?)(/|$)", rel, re.I):
            runtime_chunks.append(text)
    context.ci_text = "\n".join(ci_chunks).lower()
    context.scripts_text = "\n".join(scripts).lower()
    context.runtime_text = "\n".join(runtime_chunks).lower()
    return context


def apply_finding_quality_gate(
    findings: Iterable[Finding],
    root: Path | None,
    validation_decisions: list[dict[str, object]] | None = None,
) -> tuple[list[Finding], list[Finding], dict[str, object]]:
    incoming = list(findings)
    observations = dedupe_findings(incoming)
    validation = {str(item.get("fingerprint")): item for item in (validation_decisions or [])}
    deployment = resolve_effective_deployment(root)
    dependencies = resolve_dependency_context(root)
    semantics = build_semantic_context(root)
    for finding in observations:
        _classify(
            finding,
            validation.get(finding.fingerprint) or validation.get(str(finding.original_fingerprint or "")),
            deployment,
            dependencies,
            root,
            semantics,
        )
    _apply_supersession(observations)
    confirmed = [
        finding for finding in observations
        if finding.disposition in {FindingDisposition.confirmed, FindingDisposition.confirmed_with_compensating_control}
        and not finding.superseded_by
    ]
    counts = Counter(item.disposition.value for item in observations)
    by_scanner: dict[str, Counter] = defaultdict(Counter)
    for item in observations:
        by_scanner[item.scanner or "unknown"][item.disposition.value] += 1
    metrics: dict[str, object] = {
        "version": "promotion-gate-v4-semantic",
        "raw_observation_count": len(observations),
        "candidate_count": len(observations),
        "promoted_count": len(confirmed),
        "conditional_count": counts[FindingDisposition.conditional.value],
        "informational_count": counts[FindingDisposition.informational.value],
        "withheld_count": counts[FindingDisposition.withheld.value],
        "rejected_count": counts[FindingDisposition.rejected.value],
        "deduplicated_count": max(0, len(incoming) - len(observations)),
        "superseded_count": sum(bool(item.superseded_by) for item in observations),
        "safe_pattern_suppressed_count": sum("REJECTED_SAFE_AUTH_PATTERN" in item.disposition_reason_codes for item in observations),
        "dev_dependency_downgraded_count": sum("DOWNGRADED_DEV_ONLY_DEPENDENCY" in item.disposition_reason_codes for item in observations),
        "compensating_control_count": sum(bool(item.compensating_controls) for item in observations),
        "semantic_proof_count": sum(bool(item.promotion_proof) for item in observations),
        "negative_evidence_count": sum(len(item.negative_evidence) for item in observations),
        "reachability": semantics.reachability.value,
        "route_count": len(semantics.routes),
        "by_scanner": {scanner: dict(scanner_counts) for scanner, scanner_counts in sorted(by_scanner.items())},
        "effective_deployment": {
            "dockerfiles": deployment.dockerfiles,
            "compose_files": deployment.compose_files,
            "healthcheck": "compose" if deployment.compose_healthcheck else "dockerfile" if deployment.dockerfile_healthcheck else "unknown",
            "runtime_user": "non-root" if deployment.compose_non_root or deployment.dockerfile_non_root else "root_or_unknown",
            "published_ports": sorted(set(deployment.published_ports)),
            "docker_socket_mounted": deployment.docker_socket_mounted,
            "privileged": deployment.privileged,
            "read_only_root": deployment.read_only_root,
            "cap_drop_all": deployment.cap_drop_all,
            "tls_termination": deployment.tls_termination,
            "security_headers": sorted(set(deployment.security_headers)),
            "cors_restriction": deployment.cors_restriction,
            "provenance": deployment.provenance,
        },
    }
    return confirmed, observations, metrics


def _classify(finding: Finding, validation: dict[str, object] | None, deployment: EffectiveDeploymentContext, dependencies: DependencyContext, root: Path | None, semantics) -> None:
    profile = scanner_trust_profile(finding.scanner)
    rule_classification = scanner_rule_classification(finding.scanner, finding.original_rule_id or finding.nope_rule_id)
    finding.security_relevance = rule_classification.relevance if rule_classification else _security_relevance(finding, profile)
    finding.dependency_scope = _dependency_scope(finding, dependencies)
    validation_state = str((validation or {}).get("state") or "")
    validation_reasons = [str(item) for item in (validation or {}).get("reasons", [])]
    scanner = (finding.scanner or "").lower()
    rule = (finding.original_rule_id or finding.nope_rule_id or "").upper()
    haystack = " ".join([finding.title, finding.description, finding.category, rule]).lower()

    if finding.security_relevance in {SecurityRelevance.style_lint, SecurityRelevance.code_quality, SecurityRelevance.maintainability, SecurityRelevance.reliability, SecurityRelevance.performance}:
        return _set(finding, FindingDisposition.rejected, "REJECTED_NON_SECURITY_LINT", "The observation is lint, quality, reliability, or maintainability guidance without a concrete security consequence.", FindingPriority.none, Exposure.very_low, "no action required")
    if _healthcheck_observation(haystack) and deployment.compose_healthcheck:
        finding.compensating_controls.append("A Compose healthcheck is present in the analyzed deployment configuration.")
        finding.contradicting_evidence.extend(deployment.provenance)
        return _set(finding, FindingDisposition.rejected, "REJECTED_COMPOSE_HEALTHCHECK_PRESENT", "The isolated Dockerfile signal is superseded by an effective Compose healthcheck.", FindingPriority.none, Exposure.very_low, "no action required")
    if _root_container_observation(haystack):
        if deployment.compose_non_root:
            finding.compensating_controls.append("Compose explicitly selects a non-root runtime user.")
            return _set(finding, FindingDisposition.informational, "DOWNGRADED_COMPENSATING_CONTROL", "The image-level root signal is mitigated by the effective Compose runtime user.", FindingPriority.low, Exposure.very_low, "defense-in-depth improvement")
        if deployment.dockerfile_root:
            return _set(finding, FindingDisposition.confirmed, "PROMOTED_EFFECTIVE_ROOT_CONTAINER", "The effective container configuration remains root or has no proven non-root override.", FindingPriority.normal, Exposure.likely, "fix before production")
    if finding.security_relevance == SecurityRelevance.dependency_advisory:
        if finding.dependency_scope == DependencyScope.development:
            if _dependency_has_runtime_exposure(finding, dependencies):
                return _set(finding, FindingDisposition.confirmed, "PROMOTED_DEV_DEPENDENCY_RUNTIME_USAGE", "The package is declared as a development dependency but is imported by non-test runtime source.", FindingPriority.high, Exposure.likely, "fix before production")
            if _dependency_has_privileged_build_exposure(finding, dependencies):
                return _set(finding, FindingDisposition.confirmed, "PROMOTED_DEV_DEPENDENCY_CI_EXPOSURE", "The development dependency executes in build/CI context that can process repository input or affect artifacts.", FindingPriority.normal, Exposure.likely, "fix before production")
            return _set(finding, FindingDisposition.informational, "DOWNGRADED_DEV_ONLY_DEPENDENCY", "The affected package is development-only and no runtime, privileged CI, or deployment execution path was proven.", FindingPriority.informational, Exposure.very_low, "development-only exposure")
        if finding.dependency_scope in {DependencyScope.production, DependencyScope.optional}:
            return _set(finding, FindingDisposition.confirmed, "PROMOTED_RUNTIME_DEPENDENCY", "The advisory affects a declared runtime or optional production dependency.", FindingPriority.high if finding.severity.value in {"critical", "high"} else FindingPriority.normal, Exposure.likely, "immediate fix recommended" if finding.severity.value in {"critical", "high"} else "fix before production")
        return _set(finding, FindingDisposition.conditional, "CONDITIONAL_DEPENDENCY_SCOPE_UNKNOWN", "The advisory is valid, but NOPE could not prove whether the package is part of the deployed runtime.", FindingPriority.low, Exposure.unproven, "manual review required")
    if "gitleaks" in scanner and _placeholder_or_fixture(finding):
        return _set(finding, FindingDisposition.rejected, "REJECTED_PLACEHOLDER_OR_TEST_SECRET", "The signal is confined to example/test/fixture context or matches an explicit placeholder pattern.", FindingPriority.none, Exposure.very_low, "no action required")
    if validation_state == "rejected":
        code = "REJECTED_SAFE_AUTH_PATTERN" if "owner" in " ".join(validation_reasons).lower() else "REJECTED_CONTRADICTORY_EVIDENCE"
        finding.contradicting_evidence.extend(validation_reasons)
        return _set(finding, FindingDisposition.rejected, code, " ".join(validation_reasons) or "Deterministic contradictory evidence was found.", FindingPriority.none, Exposure.very_low, "no action required")
    if validation_state == "needs_context":
        return _set(finding, FindingDisposition.withheld, "WITHHELD_INSUFFICIENT_EVIDENCE", " ".join(validation_reasons) or "The candidate lacks sufficient deterministic evidence.", FindingPriority.low, Exposure.unproven, "manual review required")
    semantic_scanners = ("rules v2", "semgrep", "bandit", "gitleaks")
    semantic_native_rules = (
        "NOPE-SEC-",
        "NOPE-ENV-",
        "NOPE-AUTHZ-",
        "NOPE-AUTHN-",
        "NOPE-DEBUG-",
        "NOPE-STAGING-",
        "NOPE-RATE-",
        "NOPE-AI-",
        "NOPE-LOG-",
    )
    semantic = (
        evaluate_semantic_finding(finding, root, semantics)
        if any(name in scanner for name in semantic_scanners)
        or (scanner == "nope rules" and rule.startswith(semantic_native_rules))
        else None
    )
    if semantic:
        finding.proof_contract = semantic.contract
        finding.promotion_proof = semantic.proof
        finding.negative_evidence = semantic.negative_evidence
        finding.contradicting_evidence.extend(semantic.negative_evidence)
        if semantic.severity is not None:
            finding.severity = semantic.severity
        if semantic.outcome == "rejected":
            return _set(finding, FindingDisposition.rejected, semantic.reason_code, semantic.reason, FindingPriority.none, Exposure.very_low, "no action required")
        if semantic.outcome == "withheld":
            return _set(finding, FindingDisposition.withheld, semantic.reason_code, semantic.reason, FindingPriority.low, Exposure.unproven, "manual review required")
        return _set(finding, FindingDisposition.confirmed, semantic.reason_code, semantic.reason, _priority(finding), Exposure.proven, "fix before production")
    if finding.verification_state == "rules_v2_promoted" or "nope rules v2" in scanner or any("rules v2" in source.lower() for source in finding.scanner_sources):
        return _set(finding, FindingDisposition.confirmed, _rules_v2_reason(finding), "Rules v2 supplied deterministic or strongly correlated evidence with no safe-pattern contradiction.", _priority(finding), Exposure.likely, "immediate fix recommended" if finding.severity.value in {"critical", "high"} else "fix before production")
    if scanner == "nope rules" and validation_state == "promoted":
        return _set(finding, FindingDisposition.confirmed, "PROMOTED_DETERMINISTIC_NOPE_RULE", "A deterministic NOPE rule was context-validated and no contradiction was found.", _priority(finding), Exposure.likely, "fix before production")
    if profile.default_relevance == SecurityRelevance.unknown:
        return _set(finding, profile.unknown_rule_disposition, "WITHHELD_UNKNOWN_SCANNER_RULE", "Unknown scanner rules fail conservatively and require classification or corroboration before promotion.", FindingPriority.low, Exposure.unproven, "manual review required")
    if profile.requires_corroboration and len(finding.evidence) < 2 and finding.confidence not in {Confidence.confirmed, Confidence.high}:
        return _set(finding, FindingDisposition.withheld, "WITHHELD_SCANNER_CORROBORATION_REQUIRED", "This scanner profile requires stronger deterministic or corroborating evidence.", FindingPriority.low, Exposure.unproven, "manual review required")
    if profile.runtime_relevance_required and not finding.affected_route and not finding.endpoint:
        return _set(finding, FindingDisposition.conditional, "CONDITIONAL_DEPLOYMENT_UNKNOWN", "The signal is security-related, but effective runtime or deployment exposure is not proven.", FindingPriority.low, Exposure.conditional, "conditional on deployment")
    if validation_state == "promoted" and finding.security_relevance in {SecurityRelevance.direct_security_vulnerability, SecurityRelevance.configuration_weakness}:
        return _set(finding, FindingDisposition.confirmed, "PROMOTED_CONTEXT_VALIDATED_SECURITY_SIGNAL", "Scanner evidence was context-validated and classified as directly security-relevant.", _priority(finding), Exposure.likely, "fix before production")
    return _set(finding, FindingDisposition.withheld, "WITHHELD_INSUFFICIENT_EVIDENCE", "The observation remains inspectable, but deterministic promotion requirements were not met.", FindingPriority.low, Exposure.unproven, "manual review required")


def _set(finding: Finding, disposition: FindingDisposition, code: str, reason: str, priority: FindingPriority, exposure: Exposure, actionability: str) -> None:
    finding.disposition = disposition
    finding.disposition_reason_codes = [code]
    finding.disposition_reason = reason
    finding.priority = priority
    finding.exposure = exposure
    finding.actionability = actionability
    finding.deployment_relevance = "proven" if exposure in {Exposure.proven, Exposure.likely} else exposure.value
    finding.source_metadata["finding_quality"] = {
        "disposition": disposition.value,
        "reason_codes": [code],
        "reason": reason,
        "security_relevance": finding.security_relevance.value,
        "dependency_scope": finding.dependency_scope.value,
        "exposure": exposure.value,
        "priority": priority.value,
        "actionability": actionability,
        "deterministic": True,
    }


def _security_relevance(finding: Finding, profile: ScannerTrustProfile) -> SecurityRelevance:
    text = " ".join([finding.title, finding.description, finding.category]).lower()
    if finding.cve or finding.package or "depend" in finding.category.lower():
        return SecurityRelevance.dependency_advisory
    for term, relevance in NON_SECURITY_TERMS.items():
        if term in text and not any(security in text for security in SECURITY_TERMS):
            return relevance
    if "docker" in text or "container" in text or "healthcheck" in text:
        return SecurityRelevance.deployment_hardening
    if any(term in text for term in SECURITY_TERMS):
        return profile.default_relevance if profile.default_relevance != SecurityRelevance.unknown else SecurityRelevance.direct_security_vulnerability
    return profile.default_relevance


def _dependency_scope(finding: Finding, context: DependencyContext) -> DependencyScope:
    package = (finding.package or "").lower().split("@")[0]
    if not package:
        return DependencyScope.unknown
    scopes = context.scopes.get(package, set())
    for preferred in (DependencyScope.production, DependencyScope.optional, DependencyScope.development, DependencyScope.peer):
        if preferred in scopes:
            return preferred
    return DependencyScope.transitive if context.scopes else DependencyScope.unknown


def _dependency_has_privileged_build_exposure(finding: Finding, context: DependencyContext) -> bool:
    package = (finding.package or "").lower().split("@")[0]
    if not package:
        return False
    ci_or_script = f"{context.ci_text}\n{context.scripts_text}"
    return package in ci_or_script and any(term in ci_or_script for term in ("pull_request", "merge_request", "secrets.", "publish", "deploy", "build", "postinstall", "preinstall"))


def _dependency_has_runtime_exposure(finding: Finding, context: DependencyContext) -> bool:
    package = (finding.package or "").lower().split("@")[0]
    if not package:
        return False
    patterns = (f'from "{package}"', f"from '{package}'", f'require("{package}")', f"require('{package}')", f"import {package}")
    return any(pattern in context.runtime_text for pattern in patterns)


def _placeholder_or_fixture(finding: Finding) -> bool:
    path = (finding.affected_file or "").lower()
    text = " ".join([finding.title, finding.description, *(item.message for item in finding.evidence)])
    return bool(re.search(r"(^|/)(test|tests|fixtures?|examples?|docs?)(/|$)", path) or PLACEHOLDER_RE.search(text))


def _healthcheck_observation(text: str) -> bool:
    return "healthcheck" in text or "health check" in text


def _root_container_observation(text: str) -> bool:
    return ("root" in text and ("docker" in text or "container" in text or "user" in text)) or "DL3002" in text.upper()


def _rules_v2_reason(finding: Finding) -> str:
    category = finding.category.lower()
    if "auth" in category:
        return "PROMOTED_CONFIRMED_AUTHZ_GAP"
    return "PROMOTED_RULES_V2_DETERMINISTIC_EVIDENCE"


def _priority(finding: Finding) -> FindingPriority:
    if finding.severity.value == "critical":
        return FindingPriority.immediate
    if finding.severity.value == "high":
        return FindingPriority.high
    return FindingPriority.normal


def _apply_supersession(findings: list[Finding]) -> None:
    by_location: dict[tuple[str, int | None, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        category = finding.category.lower()
        family = "authorization" if "auth" in category or "idor" in category else "secret" if "secret" in category else category
        by_location[((finding.affected_file or "").lower(), finding.start_line, family)].append(finding)
    for group in by_location.values():
        confirmed = [item for item in group if item.disposition in {FindingDisposition.confirmed, FindingDisposition.confirmed_with_compensating_control}]
        if len(confirmed) < 2:
            continue
        winner = max(confirmed, key=lambda item: (item.verification_state == "rules_v2_promoted", len(item.evidence), item.confidence.value == "confirmed"))
        for item in confirmed:
            if item is winner:
                continue
            item.disposition = FindingDisposition.rejected
            item.disposition_reason_codes = ["REJECTED_SUPERSEDED"]
            item.disposition_reason = f"A more specific correlated finding ({winner.id}) captures this weakness."
            item.superseded_by = winner.id


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
