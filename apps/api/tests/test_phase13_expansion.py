import asyncio
import io
import json
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

import nope_api.main as main_module
import nope_api.scan_engine as scan_engine_module
from nope_api.auth import clear_login_rate_limits
from nope_api.config import Settings
from nope_api.db import migration_status, run_migrations
from nope_api.main import app
from nope_api.models import Confidence, Evidence, Finding, Scan, ScanMode, ScannerRun, Severity
from nope_api.scanners import BanditPlugin, SemgrepPlugin
from nope_api.storage import PostgresStore


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "apps" / "api" / "tests" / "fixtures" / "vulnerable-next"


def auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def make_zip(root: Path) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        for path in root.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    buffer.seek(0)
    return buffer.read()


def login(client: TestClient, prefix: str) -> dict:
    clear_login_rate_limits()
    suffix = uuid4().hex[:8]
    response = client.post(
        "/api/auth/login",
        json={"email": f"{prefix}-{suffix}@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()


def sample_scan(scan_id: str, owner_project_id: str | None = None) -> Scan:
    return Scan(
        id=scan_id,
        project_id=owner_project_id,
        mode=ScanMode.repository,
        status="completed",
        repository_name="phase13.zip",
        scanner_runs=[
            ScannerRun(
                scanner="Semgrep",
                status="passed",
                raw_artifact_id="art_phase13",
                raw_stdout=json.dumps({"token": "phase13_secret_value_123456"}),
                findings_count=1,
            )
        ],
        findings=[
            Finding(
                id=f"fnd_{uuid4().hex[:8]}",
                fingerprint=f"phase13-{scan_id}",
                scanner="Semgrep",
                original_rule_id="NOPE-AUTHZ-001",
                title="Invoice IDOR",
                description="Invoice lookup lacks owner scope.",
                severity=Severity.high,
                confidence=Confidence.high,
                category="Authorization",
                cwe="CWE-639",
                affected_file="app/api/invoices/[id]/route.ts",
                affected_route="/invoices/:id",
                start_line=2,
                end_line=2,
                remediation="Filter invoice by authenticated owner.",
                scanner_sources=["Semgrep"],
                fix_available=True,
                evidence=[
                    Evidence(
                        source="Semgrep",
                        file="app/api/invoices/[id]/route.ts",
                        line=2,
                        route="/invoices/:id",
                        message="findUnique uses id only.",
                    )
                ],
            )
        ],
    )


def test_phase13_unit_migrations_and_scanner_command_contracts(tmp_path):
    run_migrations(Settings())
    status = migration_status(Settings())
    assert status["pending"] == []
    assert "0001_initial" in status["applied"]

    malicious_root = tmp_path / "repo;echo owned"
    malicious_root.mkdir()
    semgrep_command = SemgrepPlugin().build_command(malicious_root)
    bandit_command = BanditPlugin().build_command(malicious_root)
    assert isinstance(semgrep_command, list)
    assert isinstance(bandit_command, list)
    assert all(";" not in item for item in semgrep_command[:-1])
    assert str(malicious_root) in bandit_command


@pytest.mark.asyncio
async def test_phase13_unit_core_repository_scan_runs_without_qwen(monkeypatch, tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "app.ts").write_text('const api_key = "phase13_secret_value_123456";', encoding="utf-8")

    monkeypatch.setattr(scan_engine_module, "scanner_plugins", lambda: [])
    scan = await scan_engine_module.run_repository_scan(
        Scan(id=f"scan_phase13_core_{uuid4().hex[:8]}", mode=ScanMode.repository),
        workspace,
        Settings(ai_provider="none", sandbox_enabled=False),
    )

    assert scan.status == "completed"
    assert scan.ai_review.status == "Not tested"
    assert any(finding.category == "Secrets" for finding in scan.findings)


def test_phase13_integration_artifact_report_and_scan_ownership():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    with TestClient(app) as client:
        owner = login(client, "phase13-owner")
        other = login(client, "phase13-other")
        owner_token = owner["token"]
        other_token = other["token"]
        owner_id = owner["user"]["id"]
        project = store.create_project(f"Phase 13 {suffix}", "repo.zip", None, owner_id)
        scan = sample_scan(f"scan_phase13_owned_{suffix}", project.id)
        store.save_scan(scan, owner_id)

        owner_scan = client.get(f"/api/scans/{scan.id}", headers=auth(owner_token))
        other_scan = client.get(f"/api/scans/{scan.id}", headers=auth(other_token))
        owner_artifact = client.get(f"/api/scans/{scan.id}/artifacts/art_phase13", headers=auth(owner_token))
        other_artifact = client.get(f"/api/scans/{scan.id}/artifacts/art_phase13", headers=auth(other_token))
        owner_report = client.get(f"/api/scans/{scan.id}/report.json", headers=auth(owner_token))
        other_report = client.get(f"/api/scans/{scan.id}/report.json", headers=auth(other_token))

    assert owner_scan.status_code == 200
    assert other_scan.status_code == 404
    assert owner_artifact.status_code == 200
    assert "phase13_secret_value_123456" not in owner_artifact.json()["stdout"]
    assert other_artifact.status_code == 404
    assert owner_report.status_code == 200
    assert other_report.status_code == 404


@pytest.mark.asyncio
async def test_phase13_e2e_login_project_zip_scan_findings_qwen_report_baseline_settings(monkeypatch):
    queued_jobs = []

    async def fake_enqueue(settings, job, force=False):
        queued_jobs.append({**job, "force": force})

    monkeypatch.setattr(main_module, "enqueue_scan_job", fake_enqueue)
    monkeypatch.setattr(scan_engine_module, "scanner_plugins", lambda: [])

    store = PostgresStore()
    with TestClient(app) as client:
        session = login(client, "phase13-e2e")
        token = session["token"]
        owner_id = session["user"]["id"]
        headers = auth(token)
        project_response = client.post(
            "/api/projects",
            headers=headers,
            json={"name": "Phase 13 E2E", "repository": "phase13.zip", "target_url": "https://example.com"},
        )
        assert project_response.status_code == 200
        project_id = project_response.json()["id"]

        upload = client.post(
            "/api/scans/repository",
            headers=headers,
            data={"project_id": project_id, "repository_name": "phase13.zip"},
            files={"file": ("phase13.zip", make_zip(FIXTURE), "application/zip")},
        )
        assert upload.status_code == 200
        scan_id = upload.json()["id"]
        assert upload.json()["status"] == "queued"
        assert queued_jobs and queued_jobs[0]["scan_id"] == scan_id

        events = client.get(f"/api/scans/{scan_id}/events", headers=headers)
        assert events.status_code == 200
        assert events.json()["status"] == "queued"

        persisted = store.get_scan(scan_id, owner_id)
        assert persisted is not None
        completed = await scan_engine_module.run_repository_scan(
            persisted,
            Path(persisted.repository_workspace_path),
            Settings(ai_provider="none", sandbox_enabled=False),
        )
        store.save_scan(completed, owner_id)

        findings = client.get(f"/api/scans/{scan_id}/findings?severity=high&page_size=5", headers=headers)
        assert findings.status_code == 200
        assert findings.json()["total"] >= 1
        finding_id = findings.json()["items"][0]["id"]

        detail = client.get(f"/api/scans/{scan_id}/findings/{finding_id}", headers=headers)
        assert detail.status_code == 200
        assert "overview" in detail.json()["tabs"]
        assert "evidence" in detail.json()["tabs"]

        ai = client.post("/api/findings/explain", headers=headers, json=findings.json()["items"][0])
        assert ai.status_code == 200
        assert ai.json()["status"] == "Not tested"

        report = client.get(f"/api/scans/{scan_id}/report.json", headers=headers)
        assert report.status_code == 200

        baseline = client.post(f"/api/scans/{scan_id}/baseline", headers=headers, json={"name": "Phase 13 baseline"})
        assert baseline.status_code == 200
        comparison = client.get(f"/api/scans/{scan_id}/compare?baseline_id={baseline.json()['id']}", headers=headers)
        assert comparison.status_code == 200

        settings_response = client.put(
            f"/api/projects/{project_id}/settings",
            headers=headers,
            json={
                "project_id": project_id,
                "target_url": "https://example.com",
                "approved_hosts": ["example.com"],
                "scanner_overrides": {"semgrep": True},
                "scan_depth": "quick",
                "authorization_confirmed": True,
            },
        )
        assert settings_response.status_code == 200
        assert settings_response.json()["target_url"] == "https://example.com"


@pytest.mark.asyncio
async def test_phase13_project_folder_rejects_low_similarity_zip(monkeypatch, tmp_path):
    queued_jobs = []

    async def fake_enqueue(settings, job, force=False):
        queued_jobs.append({**job, "force": force})

    monkeypatch.setattr(main_module, "enqueue_scan_job", fake_enqueue)

    first = tmp_path / "gpa-tracker"
    (first / "app" / "api" / "grades").mkdir(parents=True)
    (first / "app" / "api" / "grades" / "route.ts").write_text("export async function GET() {}", encoding="utf-8")
    (first / "app" / "page.tsx").write_text("export default function Page() {}", encoding="utf-8")
    (first / "package.json").write_text('{"name":"gpa-tracker"}', encoding="utf-8")

    different = tmp_path / "invoice-tool"
    (different / "src" / "billing").mkdir(parents=True)
    (different / "src" / "billing" / "invoice.py").write_text("print('invoice')", encoding="utf-8")
    (different / "pyproject.toml").write_text("[project]\nname='invoice-tool'", encoding="utf-8")

    with TestClient(app) as client:
        session = login(client, "phase13-scaffold")
        headers = auth(session["token"])
        project_response = client.post("/api/projects", headers=headers, json={"name": "GPA Tracker"})
        assert project_response.status_code == 200
        project_id = project_response.json()["id"]

        accepted = client.post(
            "/api/scans/repository",
            headers=headers,
            data={"project_id": project_id, "repository_name": "gpa-tracker.zip"},
            files={"file": ("gpa-tracker.zip", make_zip(first), "application/zip")},
        )
        assert accepted.status_code == 200
        assert accepted.json()["repository_scaffold_similarity"] == 100

        rejected = client.post(
            "/api/scans/repository",
            headers=headers,
            data={"project_id": project_id, "repository_name": "invoice-tool.zip"},
            files={"file": ("invoice-tool.zip", make_zip(different), "application/zip")},
        )
        assert rejected.status_code == 409
        assert "looks like a different project" in rejected.json()["detail"]

        forced = client.post(
            "/api/scans/repository",
            headers=headers,
            data={"project_id": project_id, "repository_name": "invoice-tool.zip", "force_scaffold": "true"},
            files={"file": ("invoice-tool.zip", make_zip(different), "application/zip")},
        )
        assert forced.status_code == 200
        assert forced.json()["repository_scaffold_similarity"] < 30

    assert len(queued_jobs) == 2


def test_phase13_security_csrf_posture_and_login_rate_limit():
    suffix = uuid4().hex[:8]
    email = f"phase13-rate-{suffix}@example.com"
    clear_login_rate_limits()

    with TestClient(app) as client:
        created = client.post("/api/auth/login", json={"email": email, "password": "correct horse battery staple"})
        assert created.status_code == 200
        assert "set-cookie" not in {key.lower() for key in created.headers.keys()}

        csrf_attempt = client.post("/api/projects", json={"name": "csrf-no-bearer"})
        assert csrf_attempt.status_code == 401

        statuses = [
            client.post("/api/auth/login", json={"email": email, "password": "wrong password"}).status_code
            for _ in range(6)
        ]

    assert statuses[:5] == [401, 401, 401, 401, 401]
    assert statuses[5] == 429


def test_phase13_security_url_ssrf_and_invalid_uploads():
    with TestClient(app) as client:
        session = login(client, "phase13-ssrf")
        headers = auth(session["token"])

        private_scan = client.post(
            "/api/scans/url",
            headers=headers,
            json={
                "mode": "url",
                "target_url": "http://127.0.0.1:8000",
                "authorization": {"confirmed": True, "approved_hosts": ["127.0.0.1"]},
            },
        )
        malformed_upload = client.post(
            "/api/scans/repository",
            headers=headers,
            files={"file": ("not-a-zip.zip", b"not a zip", "application/zip")},
        )

    assert private_scan.status_code == 400
    assert "Private network targets" in private_scan.text or "Localhost targets" in private_scan.text
    assert malformed_upload.status_code == 400
