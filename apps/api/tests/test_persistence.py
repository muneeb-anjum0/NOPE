from datetime import timedelta
from uuid import uuid4

from nope_api.config import Settings
from nope_api.db import connect, run_migrations
from nope_api.models import AIReview, Confidence, Finding, Scan, ScannerRun, ScanMode, Severity, now_utc
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


def test_phase1_contract_entities_are_persisted_through_store():
    suffix = uuid4().hex[:8]
    owner = f"user_phase1_{suffix}"
    store = PostgresStore()
    with connect(store.settings) as conn:
        conn.execute(
            "insert into local_users (id, email, password_hash) values (%s, %s, %s)",
            (owner, f"{owner}@example.com", "pbkdf2_sha256$00$00"),
        )

    project = store.create_project(
        f"Phase 1 Contract {suffix}",
        "repo.zip",
        "https://app.example.com",
        owner,
    )
    scan = Scan(
        id=f"scan_phase1_contract_{suffix}",
        project_id=project.id,
        mode=ScanMode.repository,
        status="completed",
        repository_name="repo.zip",
        branch="main",
        commit_sha=f"deadbeef{suffix}",
    )
    store.save_scan(scan, owner)

    setting = store.save_application_setting(owner, "retention", {"days": 30})
    assert setting["value"]["days"] == 30
    assert PostgresStore().get_application_setting(owner, "retention")["value"]["days"] == 30

    model_config = store.save_model_configuration(
        owner,
        "llama.cpp",
        "qwen3-8b-q4-k-m",
        "http://nope-ai:8080",
        {"context": 4096},
    )
    scanner_config = store.save_scanner_configuration(owner, "Semgrep", True, 120, {"ruleset": "nope"})
    baseline = store.create_security_baseline(project.id, scan.id, "Phase 1 baseline", {"commit": scan.commit_sha})
    drift = store.create_drift_event(baseline["id"], scan.id, "coverage_recorded", "Coverage stored.", "info")
    audit = store.record_audit_log("phase1.persistence.verified", owner, project.id, scan.id, "test")

    with connect(store.settings) as conn:
        target_count = conn.execute(
            "select count(*) as count from project_targets where project_id = %s",
            (project.id,),
        ).fetchone()["count"]
        source_count = conn.execute(
            "select count(*) as count from repository_sources where project_id = %s",
            (project.id,),
        ).fetchone()["count"]
        snapshot_count = conn.execute(
            "select count(*) as count from repository_snapshots where project_id = %s and commit_sha = %s",
            (project.id, scan.commit_sha),
        ).fetchone()["count"]

    assert target_count == 1
    assert source_count == 1
    assert snapshot_count == 1
    assert model_config["settings"]["context"] == 4096
    assert scanner_config["timeout_seconds"] == 120
    assert baseline["data"]["commit"] == scan.commit_sha
    assert drift["event_type"] == "coverage_recorded"
    assert audit["action"] == "phase1.persistence.verified"


def test_stage10_restart_persists_scan_report_baseline_drift_and_ai_cache():
    suffix = uuid4().hex[:8]
    owner = f"user_stage10_restart_{suffix}"
    store = PostgresStore()
    with connect(store.settings) as conn:
        conn.execute(
            "insert into local_users (id, email, password_hash) values (%s, %s, %s)",
            (owner, f"{owner}@example.com", "pbkdf2_sha256$00$00"),
        )
    project = store.create_project(f"Stage 10 Restart {suffix}", "repo.zip", None, owner)
    scan = Scan(
        id=f"scan_stage10_restart_{suffix}",
        project_id=project.id,
        mode=ScanMode.repository,
        status="completed",
        repository_name="repo.zip",
        ai_review=AIReview(status="Complete", provider="llama.cpp", model="qwen3-8b-q4-k-m", message="cached"),
        findings=[
            Finding(
                fingerprint=f"stage10_restart_fp_{suffix}",
                title="Restart durable finding",
                description="Finding survives process restart.",
                severity=Severity.medium,
                confidence=Confidence.high,
                category="Authorization",
                remediation="Persist it.",
                scanner_sources=["NOPE rules"],
            )
        ],
    )
    store.save_scan(scan, owner)
    store.record_scan_event(scan.id, "worker_heartbeat", owner_user_id=owner, message="worker alive", idempotency_key="stage10:heartbeat")
    baseline = store.create_security_baseline(project.id, scan.id, "Stage 10 baseline", {"scan_id": scan.id, "findings": {scan.findings[0].fingerprint: {"severity": "medium"}}})
    drift = store.create_drift_event(baseline["id"], scan.id, "model_version_change", "Model changed.", "info", {"model_version": "qwen3"})
    store.save_ai_action_cache(
        cache_key=f"stage10_cache_{suffix}",
        owner_user_id=owner,
        finding_fingerprint=scan.findings[0].fingerprint,
        action="explain",
        provider="llama.cpp",
        model="qwen3-8b-q4-k-m",
        quantization="Q4_K_M",
        prompt_version="stage10-test",
        rag_version="phase-6-v1",
        evidence_hash="evidence",
        settings_hash="settings",
        result={"summary": "durable"},
        context_metadata={"files": ["app/api/route.ts"]},
        ttl_seconds=86400,
    )

    reloaded = PostgresStore()

    assert reloaded.get_scan(scan.id, owner).findings[0].fingerprint == scan.findings[0].fingerprint
    assert reloaded.count_scan_events(scan.id, owner) >= 1
    assert reloaded.get_report_status(scan.id, "json", owner)["status"] == "completed"
    assert reloaded.get_security_baseline(baseline["id"], owner)["data"]["scan_id"] == scan.id
    assert reloaded.list_drift_events(scan.id, owner)[0]["id"] == drift["id"]
    assert reloaded.get_ai_action_cache(f"stage10_cache_{suffix}", owner)["result"]["summary"] == "durable"


def test_stage10_report_failure_state_is_retryable():
    suffix = uuid4().hex[:8]
    owner = f"user_stage10_report_{suffix}"
    store = PostgresStore()
    with connect(store.settings) as conn:
        conn.execute(
            "insert into local_users (id, email, password_hash) values (%s, %s, %s)",
            (owner, f"{owner}@example.com", "pbkdf2_sha256$00$00"),
        )
    scan = Scan(id=f"scan_stage10_report_{suffix}", mode=ScanMode.repository, status="completed")
    store.save_scan(scan, owner)

    failed = store.save_report_status(scan, "md", "failed", owner_user_id=owner, error="token=secret-value failure")
    failed_status = PostgresStore().get_report_status(scan.id, "md", owner)
    failed_body = PostgresStore().get_report(scan.id, "md", owner)
    retried = store.save_report(scan, "md", "text/markdown", "# retry succeeded", owner_user_id=owner)

    assert failed["data"]["status"] == "failed"
    assert failed_status["status"] == "failed"
    assert failed_status["error"] == "token=***REDACTED*** failure"
    assert failed_body is None
    assert retried["data"]["status"] == "completed"
    assert PostgresStore().get_report_status(scan.id, "md", owner)["byte_size"] == len("# retry succeeded")


def test_stage10_retention_cleanup_removes_old_owned_scan_state_only():
    suffix = uuid4().hex[:8]
    owner = f"user_stage10_retention_{suffix}"
    other = f"user_stage10_retention_other_{suffix}"
    store = PostgresStore()
    with connect(store.settings) as conn:
        for user in (owner, other):
            conn.execute(
                "insert into local_users (id, email, password_hash) values (%s, %s, %s)",
                (user, f"{user}@example.com", "pbkdf2_sha256$00$00"),
            )
    old_scan = Scan(id=f"scan_stage10_old_{suffix}", mode=ScanMode.repository, status="completed", started_at=now_utc() - timedelta(days=45))
    current_scan = Scan(id=f"scan_stage10_current_{suffix}", mode=ScanMode.repository, status="completed")
    other_scan = Scan(id=f"scan_stage10_other_{suffix}", mode=ScanMode.repository, status="completed", started_at=now_utc() - timedelta(days=45))
    store.save_scan(old_scan, owner)
    store.save_scan(current_scan, owner)
    store.save_scan(other_scan, other)
    with connect(store.settings) as conn:
        conn.execute(
            """
            insert into uploaded_artifacts (id, owner_user_id, scan_id, artifact_type, filename, storage_url)
            values (%s, %s, %s, %s, %s, %s)
            """,
            (f"art_stage10_old_{suffix}", owner, old_scan.id, "report_json", "old.json", "minio://old"),
        )

    result = store.cleanup_retention(owner, 30)

    assert result["scans"] == 1
    assert result["reports"] >= 1
    assert result["artifacts"] == 1
    assert PostgresStore().get_scan(old_scan.id, owner) is None
    assert PostgresStore().get_scan(current_scan.id, owner) is not None
    assert PostgresStore().get_scan(other_scan.id, other) is not None
