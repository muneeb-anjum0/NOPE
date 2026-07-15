from uuid import uuid4

from fastapi.testclient import TestClient

from nope_api.drift import baseline_snapshot, compare_scans
from nope_api.main import app
from nope_api.models import Confidence, CoverageRecord, CoverageStatus, Finding, ScannerRun, Scan, ScanMode, Severity
from nope_api.storage import PostgresStore


def finding(fp: str, title: str, *, severity: Severity = Severity.high, confidence: Confidence = Confidence.high, status: str = "new", package: str | None = None, cve: str | None = None) -> Finding:
    return Finding(
        fingerprint=fp,
        title=title,
        description=title,
        severity=severity,
        confidence=confidence,
        category="Dependencies" if package else "Authorization",
        affected_file=f"app/{fp}.ts",
        affected_route=f"/{fp}",
        package=package,
        cve=cve,
        remediation="Fix it.",
        status=status,
        scanner_sources=["Semgrep"],
    )


def scan(scan_id: str, findings: list[Finding], *, project_id: str = "project_phase8", coverage_status: CoverageStatus = CoverageStatus.verified, scanner_status: str = "passed", commit: str = "abc") -> Scan:
    return Scan(
        id=scan_id,
        project_id=project_id,
        mode=ScanMode.repository,
        status="completed",
        commit_sha=commit,
        repository_name="repo.zip",
        scanner_runs=[ScannerRun(scanner="Semgrep", version="1.0.0", status=scanner_status, coverage_categories=["Authorization"])],
        coverage=[CoverageRecord(domain="Authorization", status=coverage_status, scanners=["Semgrep"], notes="coverage")],
        findings=findings,
    )


def test_baseline_snapshot_contains_required_metadata():
    baseline = baseline_snapshot(scan("scan_base_meta", [finding("same", "Same")]))

    assert baseline.scan_id == "scan_base_meta"
    assert baseline.commit_sha == "abc"
    assert baseline.scanner_versions["Semgrep"] == "1.0.0"
    assert baseline.rule_versions["NOPE rules"] == "local"
    assert baseline.rag_version == "phase-6-v1"
    assert "same" in baseline.findings


def test_scan_comparison_detects_new_fixed_reintroduced_and_changes():
    old = scan("scan_old", [finding("fixed", "Fixed"), finding("same", "Same", severity=Severity.low), finding("reintro", "Reintro", status="fixed")])
    current = scan(
        "scan_new",
        [
            finding("same", "Same", severity=Severity.high),
            finding("newdep", "New dependency CVE", package="minimist", cve="CVE-2020-7598"),
            finding("reintro", "Reintro", status="reintroduced"),
        ],
        coverage_status=CoverageStatus.failed,
        scanner_status="failed",
    )

    comparison = compare_scans(current, old)

    assert [item.fingerprint for item in comparison.new] == ["newdep"]
    assert [item["fingerprint"] for item in comparison.fixed] == ["fixed"]
    assert [item.fingerprint for item in comparison.reintroduced] == ["reintro"]
    assert comparison.severity_changes[0].fingerprint == "same"
    assert any(event.type == "new_cve" for event in comparison.drift_events)
    assert any(event.type == "scanner_coverage_regression" for event in comparison.drift_events)
    assert comparison.incremental_scope["requires_full_scan"] is True
    assert "app/newdep.ts" in comparison.incremental_scope["changed_files"]


def test_baseline_comparison_works_from_snapshot():
    old = baseline_snapshot(scan("scan_old_snapshot", [finding("oldsecret", "Old Secret", severity=Severity.critical)]))
    current = scan("scan_current_snapshot", [finding("oldsecret", "Old Secret", severity=Severity.critical), finding("cors", "Weaker CORS policy")])

    comparison = compare_scans(current, old, baseline_id="base_1")

    assert comparison.baseline_id == "base_1"
    assert comparison.reference_scan_id == "scan_old_snapshot"
    assert any(event.type == "weaker_cors" for event in comparison.drift_events)


def test_baseline_and_drift_api_are_owner_scoped():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    old_scan = scan(f"scan_phase8_old_{suffix}", [finding(f"stable_{suffix}", "Stable")], project_id=f"project_{suffix}")
    new_scan = scan(
        f"scan_phase8_new_{suffix}",
        [finding(f"stable_{suffix}", "Stable"), finding(f"new_{suffix}", "New Secret")],
        project_id=f"project_{suffix}",
        commit="def",
    )

    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"email": f"phase8-{suffix}@example.com", "password": "correct horse battery staple"})
        token = login.json()["token"]
        user_id = login.json()["user"]["id"]
        project = store.create_project(f"Phase 8 {suffix}", "repo.zip", None, user_id)
        old_scan.project_id = project.id
        new_scan.project_id = project.id
        store.save_scan(old_scan, user_id)
        store.save_scan(new_scan, user_id)

        baseline_response = client.post(
            f"/api/scans/{old_scan.id}/baseline",
            headers={"authorization": f"Bearer {token}"},
            json={"name": "Phase 8 baseline"},
        )
        baseline = baseline_response.json()
        compare_response = client.get(
            f"/api/scans/{new_scan.id}/compare?baseline_id={baseline['id']}",
            headers={"authorization": f"Bearer {token}"},
        )
        drift_response = client.post(
            f"/api/scans/{new_scan.id}/drift?baseline_id={baseline['id']}",
            headers={"authorization": f"Bearer {token}"},
        )
        list_response = client.get(
            f"/api/scans/{new_scan.id}/drift",
            headers={"authorization": f"Bearer {token}"},
        )

    assert baseline_response.status_code == 200
    assert compare_response.status_code == 200
    assert compare_response.json()["summary"]["new"] == 1
    assert drift_response.status_code == 200
    assert drift_response.json()["persisted_events"]
    assert list_response.status_code == 200
    assert list_response.json()
