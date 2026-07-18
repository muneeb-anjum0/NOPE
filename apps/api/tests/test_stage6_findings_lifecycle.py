from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from nope_api.db import connect
from nope_api.lifecycle import LifecycleTransitionRequest
from nope_api.main import app
from nope_api.models import BaselineState, Confidence, Evidence, Finding, Scan, ScanMode, Severity
from nope_api.rules_engine import canonical_fingerprint, dedupe_findings
from nope_api.storage import PostgresStore


PASSWORD = "correct horse battery staple"


def make_finding(**overrides) -> Finding:
    data = {
        "fingerprint": f"native_{uuid4().hex}",
        "title": "Database lookup by ID may lack owner scope",
        "description": "Potential IDOR.",
        "severity": Severity.high,
        "confidence": Confidence.high,
        "category": "Authorization",
        "affected_file": "app/api/invoices/[id]/route.ts",
        "affected_route": "/api/invoices/:id",
        "start_line": 42,
        "end_line": 42,
        "symbol": "GET",
        "scanner": "Semgrep",
        "original_rule_id": "typescript.authz.idor",
        "scanner_sources": ["Semgrep"],
        "evidence": [Evidence(source="Semgrep", file="app/api/invoices/[id]/route.ts", line=42, end_line=42, route="/api/invoices/:id", message="ID lookup.")],
        "remediation": "Filter by owner or tenant.",
    }
    data.update(overrides)
    return Finding(**data)


def make_scan(scan_id: str, findings: list[Finding], project_id: str | None = None) -> Scan:
    return Scan(id=scan_id, project_id=project_id, mode=ScanMode.repository, status="completed", findings=findings)


def login(client: TestClient, email: str) -> tuple[str, str]:
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    return body["token"], body["user"]["id"]


def test_canonical_fingerprint_is_stable_and_preserves_original_scanner_fingerprint():
    first = make_finding(fingerprint="scanner-native-a", start_line=10, evidence=[Evidence(source="Semgrep", file="app/api/invoices/[id]/route.ts", line=10, message="ID lookup.")])
    second = make_finding(fingerprint="scanner-native-b", start_line=99, evidence=[Evidence(source="Semgrep", file="app/api/invoices/[id]/route.ts", line=99, message="Same ID lookup moved.")])

    merged = dedupe_findings([first])
    moved = dedupe_findings([second])

    assert merged[0].fingerprint == moved[0].fingerprint == canonical_fingerprint(merged[0])
    assert merged[0].original_fingerprint == "scanner-native-a"
    assert moved[0].original_fingerprint == "scanner-native-b"
    assert merged[0].source_metadata["original_fingerprint"] == "scanner-native-a"


def test_duplicate_sources_merge_without_losing_evidence_or_source_metadata():
    semgrep = make_finding(fingerprint="semgrep-native", scanner="Semgrep", scanner_sources=["Semgrep"], evidence=[Evidence(source="Semgrep", file="app.ts", line=7, message="semgrep")], affected_file="app.ts", start_line=7)
    zap = make_finding(fingerprint="zap-native", scanner="OWASP ZAP", scanner_sources=["OWASP ZAP"], evidence=[Evidence(source="OWASP ZAP", route="/api/invoices/:id", message="dynamic")], affected_file="app.ts", start_line=7)

    merged = dedupe_findings([semgrep, zap])

    assert len(merged) == 1
    assert set(merged[0].scanner_sources) == {"OWASP ZAP", "Semgrep"}
    assert {item.source for item in merged[0].evidence} == {"OWASP ZAP", "Semgrep"}
    assert "zap-native" in merged[0].source_metadata["merged_original_fingerprints"]


def test_lifecycle_transition_requires_valid_path_and_records_history():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    with TestClient(app) as client:
        token, user_id = login(client, f"stage6-life-{suffix}@example.com")
        scan = store.save_scan(make_scan(f"scan_stage6_life_{suffix}", dedupe_findings([make_finding(id=f"fnd_stage6_life_{suffix}")])) , user_id)
        finding = scan.findings[0]

        invalid = client.patch(
            f"/api/scans/{scan.id}/findings/{finding.id}/lifecycle",
            headers={"authorization": f"Bearer {token}"},
            json={"status": "verified", "reason": "Cannot verify before fixing.", "expected_version": finding.lifecycle_version},
        )
        confirmed = client.patch(
            f"/api/scans/{scan.id}/findings/{finding.id}/lifecycle",
            headers={"authorization": f"Bearer {token}"},
            json={"status": "confirmed", "reason": "Evidence reviewed.", "expected_version": finding.lifecycle_version},
        )
        detail = client.get(f"/api/scans/{scan.id}/findings/{finding.id}", headers={"authorization": f"Bearer {token}"})

    assert invalid.status_code == 400
    assert confirmed.status_code == 200
    updated = next(item for item in confirmed.json()["findings"] if item["id"] == finding.id)
    assert updated["status"] == "confirmed"
    assert updated["lifecycle_version"] == finding.lifecycle_version + 1
    assert any(item["event"] == "confirmed" and item["data"]["reason"] == "Evidence reviewed." for item in detail.json()["history"])


def test_suppression_requires_metadata_expires_and_reopens_automatically():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    with TestClient(app) as client:
        token, user_id = login(client, f"stage6-suppress-{suffix}@example.com")
        scan = store.save_scan(make_scan(f"scan_stage6_suppress_{suffix}", dedupe_findings([make_finding(id=f"fnd_stage6_suppress_{suffix}")])) , user_id)
        finding = scan.findings[0]
        missing_reason = client.post(f"/api/scans/{scan.id}/findings/{finding.id}/suppress", headers={"authorization": f"Bearer {token}"}, json={})
        suppressed = client.post(
            f"/api/scans/{scan.id}/findings/{finding.id}/suppress",
            headers={"authorization": f"Bearer {token}"},
            json={
                "reason": "Known test fixture for 24h.",
                "scope": "fingerprint",
                "expiry": (finding.last_seen - timedelta(seconds=1)).isoformat(),
                "expected_version": finding.lifecycle_version,
            },
        )
        reopened = client.get(f"/api/scans/{scan.id}", headers={"authorization": f"Bearer {token}"})

    assert missing_reason.status_code == 400
    assert suppressed.status_code == 200
    finding_after_read = next(item for item in reopened.json()["findings"] if item["id"] == finding.id)
    assert finding_after_read["status"] == "reopened"
    assert finding_after_read["suppression"] is None
    assert finding_after_read["suppression_expired_at"] is not None


def test_reintroduction_is_detected_from_prior_lifecycle_state():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    project = store.create_project(f"Stage6 {suffix}", None, None, None)
    original = store.save_scan(make_scan(f"scan_stage6_old_{suffix}", dedupe_findings([make_finding(id=f"fnd_stage6_old_{suffix}")]), project.id), None)
    fixed = store.transition_finding(
        original.id,
        original.findings[0].id,
        LifecycleTransitionRequest(status="confirmed", reason="Real issue."),
        None,
    )
    fixed = store.transition_finding(
        fixed.id,
        fixed.findings[0].id,
        LifecycleTransitionRequest(status="fixed", reason="Patched."),
        None,
    )

    recurring = store.save_scan(make_scan(f"scan_stage6_new_{suffix}", dedupe_findings([make_finding(id=f"fnd_stage6_new_{suffix}")]), project.id), None)

    assert recurring.findings[0].status == "reintroduced"
    assert recurring.findings[0].baseline_state == BaselineState.reintroduced
    assert recurring.findings[0].recurrence_count == 2


def test_lifecycle_update_is_owner_scoped_and_version_safe():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    with TestClient(app) as client:
        token, user_id = login(client, f"stage6-owner-{suffix}@example.com")
        other_token, _ = login(client, f"stage6-other-{suffix}@example.com")
        scan = store.save_scan(make_scan(f"scan_stage6_owner_{suffix}", dedupe_findings([make_finding(id=f"fnd_stage6_owner_{suffix}")])) , user_id)
        finding = scan.findings[0]
        unauthorized = client.patch(
            f"/api/scans/{scan.id}/findings/{finding.id}/lifecycle",
            headers={"authorization": f"Bearer {other_token}"},
            json={"status": "confirmed", "reason": "Trying another owner scan.", "expected_version": finding.lifecycle_version},
        )
        ok = client.patch(
            f"/api/scans/{scan.id}/findings/{finding.id}/lifecycle",
            headers={"authorization": f"Bearer {token}"},
            json={"status": "confirmed", "reason": "Owner reviewed.", "expected_version": finding.lifecycle_version},
        )
        stale = client.patch(
            f"/api/scans/{scan.id}/findings/{finding.id}/lifecycle",
            headers={"authorization": f"Bearer {token}"},
            json={"status": "fixing", "reason": "Stale update.", "expected_version": finding.lifecycle_version},
        )

    assert unauthorized.status_code == 404
    assert ok.status_code == 200
    assert stale.status_code == 409


def test_lifecycle_events_are_persisted_to_audit_log():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    with TestClient(app) as client:
        token, user_id = login(client, f"stage6-audit-{suffix}@example.com")
        scan = store.save_scan(make_scan(f"scan_stage6_audit_{suffix}", dedupe_findings([make_finding(id=f"fnd_stage6_audit_{suffix}")])) , user_id)
        finding = scan.findings[0]
        response = client.patch(
            f"/api/scans/{scan.id}/findings/{finding.id}/lifecycle",
            headers={"authorization": f"Bearer {token}"},
            json={"status": "confirmed", "reason": "Audit me.", "expected_version": finding.lifecycle_version},
        )

    assert response.status_code == 200
    with connect(store.settings) as conn:
        lifecycle = conn.execute("select * from finding_lifecycle_events where scan_id = %s and finding_id = %s", (scan.id, finding.id)).fetchone()
        audit = conn.execute("select * from audit_logs where scan_id = %s and action = 'finding.lifecycle.updated'", (scan.id,)).fetchone()
    assert lifecycle["new_status"] == "confirmed"
    assert lifecycle["reason"] == "Audit me."
    assert audit["data"]["finding_id"] == finding.id
