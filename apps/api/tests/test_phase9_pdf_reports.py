from uuid import uuid4

from fastapi.testclient import TestClient

import nope_api.storage as storage_module
from nope_api.drift import compare_scans
from nope_api.main import app
from nope_api.models import (
    AIReview,
    Confidence,
    CoverageRecord,
    CoverageStatus,
    Evidence,
    Finding,
    ScannerRun,
    Scan,
    ScanMode,
    Severity,
    Suppression,
)
from nope_api.reports import ReportContext, report_pdf
from nope_api.storage import PostgresStore


def finding(
    fp: str,
    title: str,
    *,
    severity: Severity = Severity.high,
    status: str = "new",
    secret: str | None = None,
) -> Finding:
    evidence = []
    if secret:
        evidence.append(Evidence(source="Gitleaks", file=".env", line=1, message=f"api_key={secret}", snippet=f"api_key={secret}"))
    return Finding(
        fingerprint=fp,
        title=title,
        description=f"{title} description {secret or ''}",
        severity=severity,
        confidence=Confidence.high,
        category="Secrets" if secret else "Authorization",
        affected_file="app/api/route.ts",
        affected_route="/api/route",
        remediation=f"Remediate {title} {secret or ''}",
        status=status,
        evidence=evidence,
    )


def scan(scan_id: str, findings: list[Finding], *, status: str = "completed", project_id: str = "project_phase9") -> Scan:
    return Scan(
        id=scan_id,
        project_id=project_id,
        mode=ScanMode.repository,
        status=status,
        verdict="Maybe. Coverage is incomplete.",
        score=58,
        coverage_percent=67,
        repository_name="repo.zip",
        commit_sha="abc123",
        scanner_runs=[
            ScannerRun(scanner="Semgrep", version="1.0.0", status="passed", coverage_categories=["Authorization"], findings_count=len(findings)),
            ScannerRun(scanner="Gitleaks", version="8.28.0", status="failed", coverage_categories=["Secrets"], message="scanner failed"),
        ],
        coverage=[
            CoverageRecord(domain="Authorization", status=CoverageStatus.verified, scanners=["Semgrep"], notes="verified"),
            CoverageRecord(domain="Secrets", status=CoverageStatus.partial, scanners=["Gitleaks"], notes="scanner failed"),
            CoverageRecord(domain="Dynamic testing", status=CoverageStatus.not_tested, scanners=[], notes="sandbox not available"),
        ],
        findings=findings,
        ai_review=AIReview(status="Failed", provider="llama.cpp", model="qwen3-8b-q4-k-m", message="Qwen unavailable during scan."),
    )


def test_pdf_report_contains_required_sections_and_redacts_secret():
    secret = "sk-phase9-secret-value-123456"
    current = scan("scan_phase9_pdf_unit", [finding("secret", "Hardcoded API key", severity=Severity.critical, secret=secret)])
    body = report_pdf(current, ReportContext())

    assert body.startswith(b"%PDF")
    assert b"NOPE Security Report" in body
    assert b"Executive Summary" in body
    assert b"Coverage" in body
    assert b"Scanner Status" in body
    assert b"Qwen Status" in body
    assert b"Limitations" in body
    assert b"Methodology" in body
    assert b"Reproducibility Metadata" in body
    assert secret.encode() not in body
    assert b"[REDACTED]" in body or b"***REDACTED***" in body


def test_pdf_report_represents_empty_partial_failed_drift_and_large_reports():
    empty = scan("scan_phase9_empty", [], status="partial")
    empty_body = report_pdf(empty, ReportContext())
    assert b"No critical findings were recorded" in empty_body
    assert b"This scan ended with status" in empty_body

    old = scan("scan_phase9_old", [finding("fixed", "Fixed finding")])
    current = scan("scan_phase9_current", [finding("new", "New finding", severity=Severity.medium)], status="partial")
    comparison = compare_scans(current, old).model_dump(mode="json")
    drift_body = report_pdf(current, ReportContext(baseline_comparison=comparison))
    assert b"Baseline Comparison" in drift_body
    assert b"Persisted or computed drift events" in drift_body
    assert b"Failed Scanners" in drift_body
    assert b"Untested Areas" in drift_body

    large = scan("scan_phase9_large", [finding(f"f{i}", f"Finding {i}", severity=Severity.low) for i in range(80)])
    large_body = report_pdf(large, ReportContext())
    assert large_body.count(b"/Type /Page") > 1


def test_pdf_report_download_is_authorized_and_status_persists(monkeypatch):
    suffix = uuid4().hex[:8]

    def fake_put_binary_artifact(settings, *, scan_id, artifact_type, name, body, content_type, extension):
        return {
            "id": f"art_phase9_{suffix}",
            "type": artifact_type,
            "filename": f"{name}.{extension}",
            "storage_url": f"minio://nope-artifacts/scans/{scan_id}/phase9.pdf",
            "size_bytes": len(body),
            "sha256": "fake-sha",
            "object_name": f"scans/{scan_id}/phase9.pdf",
            "content_type": content_type,
        }

    monkeypatch.setattr(storage_module, "put_binary_artifact", fake_put_binary_artifact)
    store = PostgresStore()

    with TestClient(app) as client:
        owner_login = client.post("/api/auth/login", json={"email": f"phase9-owner-{suffix}@example.com", "password": "correct horse battery staple"})
        other_login = client.post("/api/auth/login", json={"email": f"phase9-other-{suffix}@example.com", "password": "correct horse battery staple"})
        owner_token = owner_login.json()["token"]
        other_token = other_login.json()["token"]
        owner_id = owner_login.json()["user"]["id"]
        project = store.create_project(f"Phase 9 {suffix}", "repo.zip", None, owner_id)
        saved_scan = scan(f"scan_phase9_api_{suffix}", [finding(f"secret_{suffix}", "Secret finding", secret="sk-phase9-secret-value-abcdef")], project_id=project.id)
        saved_scan.findings[0].suppression = Suppression(reason="accepted test risk", user=owner_id)
        saved_scan.findings[0].status = "suppressed"
        store.save_scan(saved_scan, owner_id)

        response = client.get(f"/api/scans/{saved_scan.id}/report.pdf", headers={"authorization": f"Bearer {owner_token}"})
        status = client.get(f"/api/scans/{saved_scan.id}/reports/pdf/status", headers={"authorization": f"Bearer {owner_token}"})
        retry = client.post(f"/api/scans/{saved_scan.id}/reports/md/retry", headers={"authorization": f"Bearer {owner_token}"})
        retry_status = client.get(f"/api/scans/{saved_scan.id}/reports/md/status", headers={"authorization": f"Bearer {owner_token}"})
        artifact = client.get(f"/api/artifacts/art_phase9_{suffix}", headers={"authorization": f"Bearer {owner_token}"})
        unauthorized_artifact = client.get(f"/api/artifacts/art_phase9_{suffix}", headers={"authorization": f"Bearer {other_token}"})
        unauthorized = client.get(f"/api/scans/{saved_scan.id}/report.pdf", headers={"authorization": f"Bearer {other_token}"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF")
    assert b"sk-phase9-secret-value-abcdef" not in response.content
    assert status.status_code == 200
    assert status.json()["status"] == "completed"
    assert status.json()["storage_url"].startswith("minio://")
    assert status.json()["byte_size"] == len(response.content)
    assert retry.status_code == 200
    assert retry.json()["data"]["status"] == "completed"
    assert retry_status.json()["status"] == "completed"
    assert artifact.status_code == 200
    assert artifact.json()["artifact_type"] == "report_pdf"
    assert unauthorized_artifact.status_code == 404
    assert unauthorized.status_code == 404
