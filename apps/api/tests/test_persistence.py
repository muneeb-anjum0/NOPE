from uuid import uuid4

from nope_api.config import Settings
from nope_api.db import connect, run_migrations
from nope_api.models import Confidence, Finding, Scan, ScannerRun, ScanMode, Severity
from nope_api.storage import PostgresStore


def test_migrations_apply_to_local_postgres():
    settings = Settings(auth_database_url="postgresql://nope:nope@localhost:5432/nope")
    applied = run_migrations(settings)
    assert isinstance(applied, list)


def test_postgres_store_persists_scan_and_children():
    owner = None
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    project = store.create_project(f"Persistence {suffix}", "repo.zip", None, owner)
    scan = Scan(
        id=f"scan_test_{suffix}",
        project_id=project.id,
        mode=ScanMode.repository,
        status="completed",
        verdict="Maybe. Coverage is incomplete.",
        repository_name="repo.zip",
        findings=[
            Finding(
                fingerprint=f"fp_{suffix}",
                title="Persisted finding",
                description="The finding should survive a store reload.",
                severity=Severity.high,
                confidence=Confidence.medium,
                category="Authorization",
                remediation="Persist the finding and its evidence.",
                scanner_sources=["test"],
            )
        ],
        stages=[{"name": "Persisting", "status": "completed"}],
    )
    store.save_scan(scan, owner)

    reloaded = PostgresStore().get_scan(scan.id, owner)
    assert reloaded is not None
    assert reloaded.id == scan.id
    assert reloaded.findings[0].title == "Persisted finding"
    assert reloaded.stages[0]["name"] == "Persisting"

    stored_report = PostgresStore().get_report(scan.id, "md", owner)
    assert stored_report is not None
    assert stored_report[0] == "text/markdown"
    assert "Persisted finding" in stored_report[1]


def test_postgres_store_backfills_existing_empty_report_bodies():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    scan = Scan(id=f"scan_report_backfill_{suffix}", mode=ScanMode.repository)
    store.save_scan(scan, None)
    with connect(store.settings) as conn:
        conn.execute("update reports set body = '', body_sha256 = null, byte_size = 0 where scan_id = %s", (scan.id,))

    updated = store.backfill_report_bodies()
    stored_report = store.get_report(scan.id, "json", None)

    assert updated >= 1
    assert stored_report is not None
    assert scan.id in stored_report[1]


def test_user_scoped_scan_lookup_blocks_other_user():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    scan = Scan(id=f"scan_owner_{suffix}", mode=ScanMode.repository)
    store.save_scan(scan, None)
    assert store.get_scan(scan.id, "user_does_not_own_this") is None


def test_scanner_raw_output_artifact_is_recorded(monkeypatch):
    suffix = uuid4().hex[:8]
    store = PostgresStore()

    def fake_put_json_artifact(settings, *, scan_id, artifact_type, name, payload):
        return {
            "id": f"art_{suffix}",
            "type": artifact_type,
            "filename": f"{name}.json",
            "storage_url": f"minio://nope-artifacts/scans/{scan_id}/{name}.json",
            "size_bytes": 42,
            "sha256": "abc123",
        }

    monkeypatch.setattr("nope_api.storage.put_json_artifact", fake_put_json_artifact)
    scan = Scan(
        id=f"scan_artifact_{suffix}",
        mode=ScanMode.repository,
        scanner_runs=[
            ScannerRun(
                scanner="Semgrep",
                status="passed",
                raw_stdout='{"results":[]}',
                raw_stderr="",
                exit_code=0,
            )
        ],
    )

    saved = store.save_scan(scan, None)
    assert saved.scanner_runs[0].raw_artifact_id == f"art_{suffix}"
    assert saved.scanner_runs[0].raw_artifact_url.startswith("minio://")
