from datetime import timedelta
from uuid import uuid4

from nope_api.db import connect
from nope_api.models import BaselineState, Confidence, Evidence, Finding, Scan, ScanMode, Severity, Suppression, now_utc
from nope_api.rules_engine import dedupe_findings
from nope_api.storage import PostgresStore


def finding(**overrides):
    data = {
        "fingerprint": uuid4().hex,
        "title": "Finding",
        "description": "Description",
        "severity": Severity.medium,
        "confidence": Confidence.medium,
        "category": "Authorization",
        "affected_file": "app.py",
        "start_line": 10,
        "end_line": 10,
        "scanner": "test",
        "scanner_sources": ["test"],
        "evidence": [Evidence(source="test", file="app.py", line=10, message="evidence")],
        "remediation": "Fix it.",
    }
    data.update(overrides)
    return Finding(**data)


def test_duplicate_secret_merges_and_keeps_all_evidence():
    first = finding(
        fingerprint="secret-a",
        title="Hardcoded secret",
        category="Secrets",
        scanner="NOPE rules",
        scanner_sources=["NOPE rules"],
        evidence=[Evidence(source="NOPE rules", file="settings.py", line=3, message="secret")],
        affected_file="settings.py",
        start_line=3,
    )
    second = finding(
        fingerprint="secret-b",
        title="Secret detected",
        category="Secrets",
        scanner="Gitleaks",
        scanner_sources=["Gitleaks"],
        evidence=[Evidence(source="Gitleaks", file="settings.py", line=3, message="secret")],
        affected_file="settings.py",
        start_line=3,
    )

    merged = dedupe_findings([first, second])

    assert len(merged) == 1
    assert merged[0].scanner_sources == ["Gitleaks", "NOPE rules"]
    assert {item.source for item in merged[0].evidence} == {"Gitleaks", "NOPE rules"}


def test_duplicate_cve_and_package_merges_dependency_findings():
    first = finding(
        fingerprint="osv",
        scanner="OSV-Scanner",
        scanner_sources=["OSV-Scanner"],
        category="Dependencies",
        package="lodash",
        cve="CVE-2020-8203",
        severity=Severity.high,
    )
    second = finding(
        fingerprint="trivy",
        scanner="Trivy",
        scanner_sources=["Trivy"],
        category="Dependencies",
        package="lodash",
        cve="CVE-2020-8203",
        severity=Severity.medium,
    )

    merged = dedupe_findings([first, second])

    assert len(merged) == 1
    assert merged[0].severity == Severity.high
    assert merged[0].scanner_sources == ["OSV-Scanner", "Trivy"]


def test_same_issue_from_semgrep_and_custom_rule_merges_by_location():
    semgrep = finding(
        fingerprint="semgrep",
        scanner="Semgrep",
        scanner_sources=["Semgrep"],
        original_rule_id="typescript.express.security.audit.xss",
        affected_file="app.ts",
        start_line=42,
        confidence=Confidence.high,
    )
    nope = finding(
        fingerprint="nope",
        scanner="NOPE rules",
        scanner_sources=["NOPE rules"],
        nope_rule_id="nope-xss",
        affected_file="app.ts",
        start_line=42,
        confidence=Confidence.confirmed,
    )

    merged = dedupe_findings([semgrep, nope])

    assert len(merged) == 1
    assert merged[0].confidence == Confidence.confirmed
    assert set(merged[0].scanner_sources) == {"NOPE rules", "Semgrep"}


def test_static_and_dynamic_route_evidence_remain_visible():
    static = finding(
        fingerprint="static-route",
        scanner="NOPE rules",
        scanner_sources=["NOPE rules"],
        affected_route="/api/invoices/:id",
        title="Missing authorization guard",
        evidence=[Evidence(source="NOPE rules", route="/api/invoices/:id", message="static")],
    )
    dynamic = finding(
        fingerprint="dynamic-route",
        scanner="NOPE URL scanner",
        scanner_sources=["NOPE URL scanner"],
        affected_route="/api/invoices/:id",
        title="Missing authorization guard",
        evidence=[Evidence(source="NOPE URL scanner", route="/api/invoices/:id", message="dynamic")],
    )

    merged = dedupe_findings([static, dynamic])

    assert len(merged) == 1
    assert {item.source for item in merged[0].evidence} == {"NOPE URL scanner", "NOPE rules"}


def test_original_severity_is_preserved_while_normalized_severity_promotes():
    low = finding(fingerprint="one", affected_file="a.py", start_line=1, severity=Severity.low, original_severity="LOW")
    high = finding(fingerprint="two", affected_file="a.py", start_line=1, severity=Severity.high, original_severity="ERROR")

    merged = dedupe_findings([low, high])

    assert len(merged) == 1
    assert merged[0].severity == Severity.high
    assert merged[0].original_severity == "LOW"


def test_suppression_expiry_reopens_finding_on_save():
    store = PostgresStore()
    suffix = uuid4().hex[:8]
    scan = Scan(
        id=f"scan_suppression_{suffix}",
        mode=ScanMode.repository,
        findings=[
            finding(
                fingerprint=f"suppressed_{suffix}",
                suppression=Suppression(
                    reason="No longer valid.",
                    user="tester",
                    date=now_utc() - timedelta(days=2),
                    expiry=now_utc() - timedelta(days=1),
                    scope="fingerprint",
                ),
            )
        ],
    )

    saved = store.save_scan(scan, None)

    assert saved.findings[0].status == "reopened"
    assert saved.findings[0].suppression is None
    assert saved.findings[0].suppression_expired_at is not None


def test_reintroduced_finding_sets_recurrence_and_baseline_state():
    store = PostgresStore()
    suffix = uuid4().hex[:8]
    project = store.create_project(f"Phase4 {suffix}", None, None, None)
    fp = f"reintroduced_{suffix}"
    old_scan = Scan(
        id=f"scan_old_{suffix}",
        project_id=project.id,
        mode=ScanMode.repository,
        status="completed",
        findings=[finding(fingerprint=fp)],
    )
    store.save_scan(old_scan, None)
    with connect(store.settings) as conn:
        conn.execute("update finding_history set event = 'fixed' where scan_id = %s", (old_scan.id,))

    new_scan = Scan(
        id=f"scan_new_{suffix}",
        project_id=project.id,
        mode=ScanMode.repository,
        status="completed",
        findings=[finding(fingerprint=fp)],
    )

    saved = store.save_scan(new_scan, None)

    assert saved.findings[0].status == "reintroduced"
    assert saved.findings[0].baseline_state == BaselineState.reintroduced
    assert saved.findings[0].recurrence_count == 2
