from pathlib import Path

from nope_api.finding_quality import apply_finding_quality_gate, scanner_rule_classification, scanner_trust_profile
from nope_api.models import Confidence, Evidence, Finding, FindingDisposition, Severity


def finding(
    *,
    scanner: str,
    title: str,
    category: str = "Dependencies",
    rule: str = "RULE-1",
    file: str = "package-lock.json",
    package: str | None = None,
    cve: str | None = None,
    confidence: Confidence = Confidence.high,
) -> Finding:
    return Finding(
        scanner=scanner,
        scanner_sources=[scanner],
        original_rule_id=rule,
        fingerprint=f"{scanner}:{rule}:{file}:{package}",
        title=title,
        description=title,
        severity=Severity.high,
        original_severity="HIGH",
        confidence=confidence,
        category=category,
        affected_file=file,
        package=package,
        cve=cve,
        remediation="Review and remediate.",
        evidence=[Evidence(source=scanner, file=file, message=title)],
    )


def gate(items: list[Finding], root: Path, decisions: list[dict[str, object]] | None = None):
    return apply_finding_quality_gate(items, root, decisions)


def test_dev_dependency_is_informational_without_runtime_or_ci_exposure(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"devDependencies":{"eslint-plugin-demo":"1.0.0"}}')
    item = finding(scanner="OSV-Scanner", title="eslint plugin advisory", package="eslint-plugin-demo", cve="CVE-2026-1")

    confirmed, observations, metrics = gate([item], tmp_path)

    assert confirmed == []
    assert observations[0].disposition == FindingDisposition.informational
    assert observations[0].dependency_scope.value == "development"
    assert observations[0].original_severity == "HIGH"
    assert observations[0].priority.value == "informational"
    assert "DOWNGRADED_DEV_ONLY_DEPENDENCY" in observations[0].disposition_reason_codes
    assert metrics["dev_dependency_downgraded_count"] == 1


def test_dev_dependency_with_untrusted_ci_build_exposure_stays_confirmed(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"devDependencies":{"dangerous-builder":"1.0.0"},"scripts":{"build":"dangerous-builder"}}')
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "build.yml").write_text("on: pull_request\nrun: npm run build\nenv: TOKEN: ${{ secrets.TOKEN }}")
    item = finding(scanner="OSV-Scanner", title="builder code execution advisory", package="dangerous-builder", cve="CVE-2026-2")

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == observations
    assert observations[0].disposition == FindingDisposition.confirmed
    assert "PROMOTED_DEV_DEPENDENCY_CI_EXPOSURE" in observations[0].disposition_reason_codes


def test_dev_dependency_imported_by_runtime_source_stays_confirmed(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"devDependencies":{"runtime-parser":"1.0.0"}}')
    source = tmp_path / "src" / "server.ts"
    source.parent.mkdir()
    source.write_text('import parser from "runtime-parser"; export function handle(value) { return parser(value) }')
    item = finding(scanner="OSV-Scanner", title="parser execution advisory", package="runtime-parser", cve="CVE-2026-3")

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == observations
    assert "PROMOTED_DEV_DEPENDENCY_RUNTIME_USAGE" in observations[0].disposition_reason_codes


def test_compose_healthcheck_rejects_isolated_missing_healthcheck_signal(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:24\nCMD [\"node\",\"server.js\"]")
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n    healthcheck:\n      test: [CMD, curl, -f, http://localhost]\n")
    item = finding(scanner="Hadolint", title="Dockerfile has no HEALTHCHECK", category="Containers", rule="DL-HEALTH", file="Dockerfile")

    confirmed, observations, metrics = gate([item], tmp_path)

    assert confirmed == []
    assert observations[0].disposition == FindingDisposition.rejected
    assert "REJECTED_COMPOSE_HEALTHCHECK_PRESENT" in observations[0].disposition_reason_codes
    assert metrics["compensating_control_count"] == 1


def test_missing_healthcheck_without_deployment_context_is_not_confirmed(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:24\nCMD [\"node\",\"server.js\"]")
    item = finding(scanner="Hadolint", title="Dockerfile has no HEALTHCHECK", category="Containers", rule="DL-HEALTH", file="Dockerfile")

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == []
    assert observations[0].disposition in {FindingDisposition.conditional, FindingDisposition.rejected}


def test_compose_non_root_override_downgrades_image_root_signal(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:24\nUSER root\n")
    (tmp_path / "compose.yml").write_text('services:\n  web:\n    build: .\n    user: "1000:1000"\n')
    item = finding(scanner="Hadolint", title="Docker container runs as root", category="Containers", rule="DL3002", file="Dockerfile")

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == []
    assert observations[0].disposition == FindingDisposition.informational
    assert "DOWNGRADED_COMPENSATING_CONTROL" in observations[0].disposition_reason_codes


def test_effective_root_container_remains_confirmed(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:24\nUSER root\n")
    item = finding(scanner="Hadolint", title="Docker container runs as root", category="Containers", rule="DL3002", file="Dockerfile")

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == observations
    assert "PROMOTED_EFFECTIVE_ROOT_CONTAINER" in observations[0].disposition_reason_codes


def test_safe_authorization_evidence_rejects_candidate_even_with_security_title(tmp_path: Path):
    source = tmp_path / "app" / "api" / "documents" / "route.ts"
    source.parent.mkdir(parents=True)
    source.write_text("const document = await db.document.findFirst({ where: { id: params.id, ownerId: session.user.id } });")
    item = finding(scanner="Semgrep", title="Potential IDOR", category="Authorization", rule="idor", file="app/api/documents/route.ts")
    decisions = [{"fingerprint": item.fingerprint, "state": "rejected", "reasons": ["Owner predicate binds the query to session.user.id."]}]

    _, observations, metrics = gate([item], tmp_path, decisions)

    assert observations[0].disposition == FindingDisposition.rejected
    assert "REJECTED_SAFE_AUTH_PATTERN" in observations[0].disposition_reason_codes
    assert metrics["safe_pattern_suppressed_count"] == 1


def test_misleading_helper_name_does_not_suppress_without_validated_evidence(tmp_path: Path):
    source = tmp_path / "app" / "api" / "documents" / "route.ts"
    source.parent.mkdir(parents=True)
    source.write_text("function checkOwner() { return true }\nreturn db.document.findUnique({ where: { id: params.id } })")
    item = finding(scanner="Semgrep", title="Potential IDOR", category="Authorization", rule="idor", file="app/api/documents/route.ts")

    _, observations, _ = gate([item], tmp_path)

    assert observations[0].disposition != FindingDisposition.rejected
    assert "REJECTED_SAFE_AUTH_PATTERN" not in observations[0].disposition_reason_codes


def test_unknown_scanner_rule_fails_conservatively(tmp_path: Path):
    item = finding(scanner="Mystery Linter", title="Possibly odd construct", category="Unknown", confidence=Confidence.low)

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == []
    assert observations[0].disposition == FindingDisposition.withheld
    assert "WITHHELD_UNKNOWN_SCANNER_RULE" in observations[0].disposition_reason_codes


def test_rules_v2_promotion_requires_stage15_3_semantic_proof(tmp_path: Path):
    item = finding(scanner="NOPE Rules v2", title="Confirmed authorization gap", category="Authorization", rule="NOPE-CORR-IDOR-001")
    item.verification_state = "rules_v2_promoted"

    confirmed, observations, _ = gate([item], tmp_path)

    assert confirmed == []
    assert observations[0].disposition == FindingDisposition.rejected
    assert "REJECTED_NO_SERVER_ROUTE" in observations[0].disposition_reason_codes


def test_scanner_registry_covers_integrated_scanners():
    scanners = [
        "Semgrep", "Gitleaks", "OSV-Scanner", "Trivy", "npm audit", "pnpm audit",
        "yarn audit", "pip-audit", ".NET package audit", "cargo audit", "govulncheck",
        "composer audit", "bundler-audit", "Checkov", "Hadolint", "Bandit",
        "OWASP ZAP", "NOPE URL scanner", "NOPE rules", "NOPE Rules v2",
    ]
    assert all(scanner_trust_profile(scanner).default_relevance.value != "unknown" for scanner in scanners)
    assert scanner_rule_classification("Hadolint", "DL3002").reason_code == "CONDITIONAL_EFFECTIVE_RUNTIME_USER"
    assert scanner_rule_classification("Hadolint", "DL4006").noise_class == "docker_best_practice"
