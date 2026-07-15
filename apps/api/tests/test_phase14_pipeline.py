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
from nope_api.db import connect
from nope_api.main import app
from nope_api.models import AIReview, Confidence, CoverageRecord, CoverageStatus, Evidence, Finding, ScanMode, ScannerRun, Severity
from nope_api.queue import execute_scan_job
from nope_api.storage import PostgresStore


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "apps" / "api" / "tests" / "fixtures" / "vulnerable-next"


def auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def make_zip(root: Path, *, extra_files: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        for path in root.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
        for name, content in (extra_files or {}).items():
            archive.writestr(name, content)
    buffer.seek(0)
    return buffer.read()


def login(client: TestClient, prefix: str) -> dict:
    clear_login_rate_limits()
    response = client.post(
        "/api/auth/login",
        json={"email": f"{prefix}-{uuid4().hex[:8]}@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()


class Phase14Scanner:
    name = "Phase 14 scanner"

    def __init__(self, *, failed: bool = False) -> None:
        self.failed = failed

    def execute(self, root: Path, settings: Settings) -> tuple[ScannerRun, list[Finding]]:
        if self.failed:
            return (
                ScannerRun(
                    scanner=self.name,
                    status="failed",
                    coverage_categories=["Rate limiting"],
                    message="scanner timeout while analyzing ***REDACTED***",
                    command=["phase14-scanner", str(root)],
                    exit_code=124,
                ),
                [],
            )

        findings = [
            Finding(
                fingerprint="phase14-stable-idor",
                scanner=self.name,
                original_rule_id="PHASE14-IDOR",
                title="Stable invoice IDOR",
                description="Invoice route is reachable without owner scope.",
                severity=Severity.high,
                confidence=Confidence.high,
                category="Authorization",
                affected_file="app/api/invoices/[id]/route.ts",
                affected_route="/invoices/:id",
                scanner_sources=[self.name],
                evidence=[
                    Evidence(
                        source=self.name,
                        file="app/api/invoices/[id]/route.ts",
                        route="/invoices/:id",
                        message="findUnique is used without owner scoping.",
                    )
                ],
                remediation="Filter invoice records by the authenticated owner.",
                fix_available=True,
            )
        ]
        if (root / "app" / "api" / "phase14" / "route.ts").exists():
            findings.append(
                Finding(
                    fingerprint="phase14-new-secret",
                    scanner=self.name,
                    original_rule_id="PHASE14-SECRET",
                    title="New phase 14 secret",
                    description="A newly added route contains a secret-like value.",
                    severity=Severity.critical,
                    confidence=Confidence.high,
                    category="Secrets",
                    affected_file="app/api/phase14/route.ts",
                    affected_route="/phase14",
                    scanner_sources=[self.name],
                    evidence=[
                        Evidence(
                            source=self.name,
                            file="app/api/phase14/route.ts",
                            route="/phase14",
                            message="Secret-like value added in modified scan.",
                        )
                    ],
                    remediation="Move the value to managed secret storage and rotate it.",
                    fix_available=True,
                )
            )
        return (
            ScannerRun(
                scanner=self.name,
                status="passed",
                coverage_categories=["Authorization", "Secrets"],
                findings_count=len(findings),
                command=["phase14-scanner", str(root)],
                exit_code=0,
            ),
            findings,
        )


async def fake_url_scan(target_url: str):
    return (
        [
            Finding(
                fingerprint="phase14-url-headers",
                scanner="NOPE URL scanner",
                original_rule_id="PHASE14-URL",
                title="URL security header gap",
                description="The target URL is missing a hardening header.",
                severity=Severity.medium,
                confidence=Confidence.medium,
                category="Security headers",
                affected_route=target_url,
                scanner_sources=["NOPE URL scanner"],
                evidence=[Evidence(source="NOPE URL scanner", endpoint=target_url, message="Header check completed.")],
                remediation="Set the missing security header.",
            )
        ],
        [
            ScannerRun(
                scanner="NOPE URL scanner",
                status="passed",
                coverage_categories=["URL scanning", "Security headers"],
                findings_count=1,
            )
        ],
        [CoverageRecord(domain="URL scanning", status=CoverageStatus.verified, scanners=["NOPE URL scanner"], notes="URL checks completed.")],
    )


async def fake_ai_review(settings: Settings, findings: list[Finding], root: Path | None = None, scan=None):
    return AIReview(
        status="Complete",
        provider="llama.cpp",
        model="qwen3-8b-q4-k-m",
        evidence_provided=[finding.fingerprint for finding in findings[:3]],
        confidence=Confidence.medium,
        message="Phase 14 deterministic Qwen contract completed.",
    )


async def failed_ai_review(settings: Settings, findings: list[Finding], root: Path | None = None, scan=None):
    return AIReview(status="Failed", provider="llama.cpp", model="qwen3-8b-q4-k-m", message="Qwen unavailable.")


def fake_sandbox(root: Path, settings: Settings):
    return (
        [ScannerRun(scanner="NOPE sandbox", status="skipped", coverage_categories=["Dynamic testing"], message="No sandbox manifest.")],
        [],
        [CoverageRecord(domain="Dynamic testing", status=CoverageStatus.not_applicable, scanners=["NOPE sandbox"], notes="No sandbox manifest.")],
        [{"status": "skipped", "reason": "unsupported sandbox"}],
    )


@pytest.mark.asyncio
async def test_phase14_full_pipeline_success_baseline_second_scan_drift_and_reports(monkeypatch):
    queued_jobs: list[dict] = []

    async def capture_enqueue(settings, job, force=False):
        queued_jobs.append({**job, "force": force})
        return {"queued": True, "job_id": f"job_{len(queued_jobs)}", "queue_depth": len(queued_jobs)}

    async def not_cancelled(settings, scan_id):
        return False

    monkeypatch.setattr(main_module, "enqueue_scan_job", capture_enqueue)
    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", not_cancelled)
    monkeypatch.setattr(scan_engine_module, "scanner_plugins", lambda: [Phase14Scanner()])
    monkeypatch.setattr(scan_engine_module, "scan_url", fake_url_scan)
    monkeypatch.setattr(scan_engine_module, "run_ai_review", fake_ai_review)
    monkeypatch.setattr(scan_engine_module, "run_sandbox_assessment", fake_sandbox)

    store = PostgresStore()
    settings = Settings(ai_provider="none", sandbox_enabled=False)
    with TestClient(app) as client:
        session = login(client, "phase14-full")
        headers = auth(session["token"])
        owner_id = session["user"]["id"]

        project_response = client.post(
            "/api/projects",
            headers=headers,
            json={"name": "Phase 14 pipeline", "repository": "phase14.zip", "target_url": "https://example.com"},
        )
        assert project_response.status_code == 200
        project_id = project_response.json()["id"]

        first = client.post(
            "/api/scans/full",
            headers=headers,
            data={
                "project_id": project_id,
                "target_url": "https://example.com",
                "authorization_confirmed": "true",
                "approved_hosts": "example.com",
                "repository_name": "phase14-first.zip",
                "branch": "main",
                "commit_sha": "phase14a",
            },
            files={"file": ("phase14-first.zip", make_zip(FIXTURE), "application/zip")},
        )
        assert first.status_code == 200
        first_scan_id = first.json()["id"]
        assert queued_jobs[-1]["scan_id"] == first_scan_id
        assert queued_jobs[-1]["mode"] == ScanMode.full.value

        await execute_scan_job(settings, queued_jobs[-1])
        first_scan = store.get_scan(first_scan_id, owner_id)
        assert first_scan is not None
        assert first_scan.status == "completed"
        assert first_scan.mode == ScanMode.full
        assert first_scan.stack
        assert any(item.route == "/invoices/:id" for item in first_scan.attack_surface)
        assert first_scan.code_graph.nodes
        assert any(run.scanner == "Phase 14 scanner" and run.status == "passed" for run in first_scan.scanner_runs)
        assert any(run.scanner == "NOPE URL scanner" for run in first_scan.scanner_runs)
        assert any(stage["name"] == "Running URL checks" and stage["status"] == "completed" for stage in first_scan.stages)
        assert first_scan.ai_review.status == "Complete"
        assert first_scan.coverage_percent > 0

        with connect(Settings()) as conn:
            snapshot_count = conn.execute(
                "select count(*) as count from repository_snapshots where project_id = %s and commit_sha = %s",
                (project_id, "phase14a"),
            ).fetchone()["count"]
        assert snapshot_count >= 1

        finding_response = client.get(f"/api/scans/{first_scan_id}/findings?query=invoice", headers=headers)
        assert finding_response.status_code == 200
        assert finding_response.json()["total"] >= 1
        report_json = client.get(f"/api/scans/{first_scan_id}/report.json", headers=headers)
        report_pdf = client.get(f"/api/scans/{first_scan_id}/report.pdf", headers=headers)
        assert report_json.status_code == 200
        assert report_pdf.status_code == 200
        assert report_pdf.headers["content-type"].startswith("application/pdf")

        baseline_response = client.post(f"/api/scans/{first_scan_id}/baseline", headers=headers, json={"name": "Phase 14 baseline"})
        assert baseline_response.status_code == 200
        baseline_id = baseline_response.json()["id"]

        second = client.post(
            "/api/scans/full",
            headers=headers,
            data={
                "project_id": project_id,
                "target_url": "https://example.com",
                "authorization_confirmed": "true",
                "approved_hosts": "example.com",
                "repository_name": "phase14-second.zip",
                "branch": "main",
                "commit_sha": "phase14b",
            },
            files={
                "file": (
                    "phase14-second.zip",
                    make_zip(
                        FIXTURE,
                        extra_files={
                            "app/api/phase14/route.ts": 'export async function GET() { return Response.json({ token: "phase14_secret_value_123456" }) }'
                        },
                    ),
                    "application/zip",
                )
            },
        )
        assert second.status_code == 200
        second_scan_id = second.json()["id"]
        await execute_scan_job(settings, queued_jobs[-1])

        comparison = client.get(f"/api/scans/{second_scan_id}/compare?baseline_id={baseline_id}", headers=headers)
        drift = client.post(f"/api/scans/{second_scan_id}/drift?baseline_id={baseline_id}", headers=headers)
        listed_drift = client.get(f"/api/scans/{second_scan_id}/drift", headers=headers)

    assert comparison.status_code == 200
    assert comparison.json()["summary"]["new"] >= 1
    assert "phase14_secret_value_123456" not in json.dumps(comparison.json())
    assert drift.status_code == 200
    assert drift.json()["persisted_events"]
    assert listed_drift.status_code == 200
    assert listed_drift.json()


@pytest.mark.asyncio
async def test_phase14_failure_paths_reduce_coverage_and_preserve_state(monkeypatch, tmp_path):
    scan_id = f"scan_phase14_failure_{uuid4().hex[:8]}"
    scan = main_module.store.save_scan(
        main_module.Scan(
            id=scan_id,
            mode=ScanMode.full,
            status="queued",
            target_url="https://example.com",
            repository_name="phase14-failure.zip",
            repository_workspace_path=str(tmp_path),
        ),
        None,
    )

    async def not_cancelled(settings, scan_id):
        return False

    async def record_cancel(settings, scan_id):
        return None

    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", not_cancelled)
    monkeypatch.setattr(main_module, "request_scan_cancel", record_cancel)
    monkeypatch.setattr(scan_engine_module, "scanner_plugins", lambda: [Phase14Scanner(failed=True)])
    monkeypatch.setattr(scan_engine_module, "scan_url", fake_url_scan)
    monkeypatch.setattr(scan_engine_module, "run_ai_review", failed_ai_review)
    monkeypatch.setattr(scan_engine_module, "run_sandbox_assessment", fake_sandbox)

    (tmp_path / "app" / "api" / "invoices" / "[id]").mkdir(parents=True)
    (tmp_path / "app" / "api" / "invoices" / "[id]" / "route.ts").write_text(
        "export async function GET() { return Response.json({ ok: true }) }",
        encoding="utf-8",
    )

    await execute_scan_job(
        Settings(ai_provider="none", sandbox_enabled=False),
        {"scan_id": scan.id, "owner_user_id": None, "mode": ScanMode.full.value, "repository_workspace_path": str(tmp_path)},
    )
    completed = main_module.store.get_scan(scan_id)

    assert completed is not None
    assert completed.status == "partial"
    assert any(run.scanner == "Phase 14 scanner" and run.status == "failed" for run in completed.scanner_runs)
    assert any(record.domain == "Rate limiting" and record.status == CoverageStatus.failed for record in completed.coverage)
    assert any(record.domain == "Qwen AI review" and record.status == CoverageStatus.failed for record in completed.coverage)
    assert any(record.domain == "Dynamic testing" and record.status == CoverageStatus.not_applicable for record in completed.coverage)
    assert "phase14_secret_value_123456" not in json.dumps(completed.model_dump(mode="json"))

    with TestClient(app) as client:
        session = login(client, "phase14-cancel")
        headers = auth(session["token"])
        cancel_scan = main_module.Scan(id=f"scan_phase14_cancel_{uuid4().hex[:8]}", mode=ScanMode.repository, status="queued")
        main_module.store.save_scan(cancel_scan, session["user"]["id"])
        cancelled = client.post(f"/api/scans/{cancel_scan.id}/cancel", headers=headers)
        malformed = client.post(
            "/api/scans/repository",
            headers=headers,
            files={"file": ("not-a-zip.zip", b"nope", "application/zip")},
        )

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert malformed.status_code == 400
