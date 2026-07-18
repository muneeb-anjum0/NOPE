from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from nope_api.config import Settings
from nope_api.models import AIReview, Scan, ScannerRun, ScanMode
from nope_api.queue import _handle_job_failure, _json, _requeue_stuck_jobs, execute_scan_job, scan_events
from nope_api.storage import PostgresStore


def _owner(store: PostgresStore, suffix: str) -> str:
    owner = f"user_stage2_{suffix}"
    from nope_api.db import connect

    with connect(store.settings) as conn:
        conn.execute(
            "insert into local_users (id, email, password_hash) values (%s, %s, %s) on conflict do nothing",
            (owner, f"{owner}@example.com", "pbkdf2_sha256$00$00"),
        )
    return owner


def test_stage2_event_storage_is_ordered_idempotent_paginated_and_redacted():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    owner = _owner(store, suffix)
    scan = Scan(id=f"scan_stage2_store_{suffix}", mode=ScanMode.url, status="running")
    store.save_scan(scan, owner)

    first = store.record_scan_event(
        scan.id,
        "scan_started",
        owner_user_id=owner,
        new_state="running",
        progress=20,
        message="started",
        idempotency_key="same-key",
    )
    duplicate = store.record_scan_event(
        scan.id,
        "scan_started",
        owner_user_id=owner,
        new_state="running",
        progress=10,
        message="token=sk-live-secret",
        idempotency_key="same-key",
    )
    failed = store.record_scan_event(
        scan.id,
        "scanner_failed",
        owner_user_id=owner,
        new_state="failed",
        progress=15,
        message="scanner failed with api_key=abc123",
        error_details="password=hunter2",
        idempotency_key="failure",
    )

    assert first and duplicate and failed
    assert first.id == duplicate.id
    assert failed.sequence == first.sequence + 1
    assert failed.progress == 20
    assert "***REDACTED***" in failed.message
    assert "***REDACTED***" in (failed.error_details or "")

    for index in range(20):
        store.record_scan_event(
            scan.id,
            "stage_progress",
            owner_user_id=owner,
            stage_id=f"stage:{index}",
            new_state="running",
            progress=20 + index,
            message=f"progress {index}",
            idempotency_key=f"progress:{index}",
        )

    first_page = store.list_scan_events(scan.id, owner, limit=5)
    assert first_page is not None
    assert first_page["has_more"] is True
    assert first_page["events"][0]["sequence"] == 1
    second_page = store.list_scan_events(scan.id, owner, after_sequence=first_page["next_after_sequence"], limit=10)
    assert second_page is not None
    assert second_page["events"][0]["sequence"] == 6


@pytest.mark.asyncio
async def test_stage2_completed_scan_backfills_non_empty_timeline_after_restart():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    owner = _owner(store, suffix)
    scan = Scan(
        id=f"scan_stage2_backfill_{suffix}",
        mode=ScanMode.repository,
        status="completed",
        verdict="NOPE. Do not ship this.",
        stages=[{"name": "Detecting stack", "status": "completed"}],
        scanner_runs=[ScannerRun(scanner="NOPE rules", status="passed", findings_count=1)],
        ai_review=AIReview(status="Complete", provider="llama.cpp", message="Reviewed evidence."),
    )
    store.save_scan(scan, owner)
    assert store.count_scan_events(scan.id, owner) == 0

    reloaded = PostgresStore().get_scan(scan.id, owner)
    assert reloaded is not None
    payload = await scan_events(reloaded, owner)

    assert payload["total"] > 0
    assert payload["events"][0]["event_type"] == "scan_created"
    assert payload["events"][-1]["event_type"] == "scan_completed"


@pytest.mark.asyncio
async def test_stage2_successful_scan_records_complete_durable_timeline(monkeypatch):
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    owner = _owner(store, suffix)
    scan = Scan(id=f"scan_stage2_success_{suffix}", mode=ScanMode.url, target_url="https://example.com")
    store.save_scan(scan, owner)

    async def not_cancelled(settings, scan_id):
        return False

    async def fake_url_scan(updated, settings, progress_callback=None, cancellation_checker=None):
        updated.stages.append({"name": "Running scanner plugins", "status": "running"})
        if progress_callback:
            await progress_callback(updated)
        updated.scanner_runs.append(ScannerRun(scanner="NOPE rules", status="passed", findings_count=0))
        updated.stages[-1]["status"] = "completed"
        updated.stages.append({"name": "Running Qwen review", "status": "running"})
        if progress_callback:
            await progress_callback(updated)
        updated.ai_review = AIReview(status="Complete", provider="llama.cpp", message="Reviewed evidence.")
        updated.stages[-1]["status"] = "completed"
        updated.status = "completed"
        if progress_callback:
            await progress_callback(updated)
        return updated

    monkeypatch.setattr("nope_api.queue.store", store)
    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", not_cancelled)
    monkeypatch.setattr("nope_api.queue.run_url_only_scan", fake_url_scan)

    await execute_scan_job(Settings(), {"scan_id": scan.id, "owner_user_id": owner, "mode": "url", "job_id": f"job_{suffix}"})

    payload = await scan_events(PostgresStore().get_scan(scan.id, owner), owner)
    types = [event["event_type"] for event in payload["events"]]
    assert "scan_started" in types
    assert "stage_progress" in types
    assert "scanner_started" in types
    assert "scanner_completed" in types
    assert "qwen_started" in types
    assert "qwen_completed" in types
    assert "report_started" in types
    assert "report_completed" in types
    assert "scan_completed" in types
    assert payload["progress"] == 100


@pytest.mark.asyncio
async def test_stage2_failure_retry_timeout_and_stuck_worker_events(monkeypatch):
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    owner = _owner(store, suffix)
    scan = Scan(id=f"scan_stage2_retry_{suffix}", mode=ScanMode.url, target_url="https://example.com")
    scan.scanner_runs.append(ScannerRun(scanner="Semgrep", status="failed", message="scanner timeout"))
    store.save_scan(scan, owner)
    pushed: list[str] = []

    class FakeRedis:
        def __init__(self):
            stale_job = {
                "scan_id": scan.id,
                "owner_user_id": owner,
                "mode": "url",
                "job_id": f"job_stale_{suffix}",
                "attempt": 1,
                "started_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
            }
            self.processing = [_json(stale_job)]

        async def hset(self, *args, **kwargs):
            return 1

        async def rpush(self, key, payload):
            pushed.append(payload)
            return len(pushed)

        async def delete(self, key):
            return 1

        async def lrange(self, key, start, end):
            return list(self.processing)

        async def lrem(self, key, count, payload):
            self.processing = [item for item in self.processing if item != payload]
            return 1

    async def not_cancelled(settings, scan_id):
        return False

    monkeypatch.setattr("nope_api.queue.store", store)
    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", not_cancelled)

    redis = FakeRedis()
    await _handle_job_failure(
        Settings(),
        redis,
        {"scan_id": scan.id, "owner_user_id": owner, "mode": "url", "job_id": f"job_{suffix}", "attempt": 1, "max_attempts": 2},
        TimeoutError("whole scan timed out"),
        timed_out=True,
    )
    requeued = await _requeue_stuck_jobs(redis)

    events = store.list_scan_events(scan.id, owner, limit=100)
    types = [event["event_type"] for event in events["events"]]
    assert pushed
    assert requeued == 1
    assert "scanner_timed_out" in types
    assert "retry_scheduled" in types
    assert "worker_lost" in types
    assert "scan_partial" in types


def test_stage2_events_endpoint_is_authorized_and_paginated(monkeypatch):
    from nope_api.main import app

    suffix = uuid4().hex[:8]

    async def fake_enqueue(settings, job, **kwargs):
        return {"queued": True, "job_id": f"job_{suffix}", "queue_depth": 1}

    async def fake_cancel(settings, scan_id):
        return None

    monkeypatch.setattr("nope_api.main.enqueue_scan_job", fake_enqueue)
    monkeypatch.setattr("nope_api.main.request_scan_cancel", fake_cancel)

    with TestClient(app) as client:
        first_login = client.post("/api/auth/login", json={"email": f"stage2-a-{suffix}@example.com", "password": "correct horse battery staple"})
        second_login = client.post("/api/auth/login", json={"email": f"stage2-b-{suffix}@example.com", "password": "correct horse battery staple"})
        first_token = first_login.json()["token"]
        second_token = second_login.json()["token"]

        created = client.post(
            "/api/scans/url",
            headers={"authorization": f"Bearer {first_token}"},
            json={"mode": "url", "target_url": "https://example.com", "authorization": {"confirmed": True}},
        )
        assert created.status_code == 200
        scan_id = created.json()["id"]

        own = client.get(f"/api/scans/{scan_id}/events?limit=1", headers={"authorization": f"Bearer {first_token}"})
        cancelled = client.post(f"/api/scans/{scan_id}/cancel", headers={"authorization": f"Bearer {first_token}"})
        after_cancel = client.get(f"/api/scans/{scan_id}/events?limit=100", headers={"authorization": f"Bearer {first_token}"})
        other = client.get(f"/api/scans/{scan_id}/events", headers={"authorization": f"Bearer {second_token}"})

    assert own.status_code == 200
    assert own.json()["events"]
    assert "has_more" in own.json()
    assert cancelled.status_code == 200
    assert {"cancellation_requested", "cancellation_acknowledged", "scan_cancelled"}.issubset(
        {event["event_type"] for event in after_cancel.json()["events"]}
    )
    assert other.status_code == 404
