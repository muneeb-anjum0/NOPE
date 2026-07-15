import pytest

from nope_api.config import Settings
from nope_api.models import Scan, ScanMode
from nope_api.queue import _handle_job_failure, execute_scan_job, scan_events


@pytest.mark.asyncio
async def test_execute_scan_job_runs_url_scan_and_persists(monkeypatch):
    saved_statuses: list[str] = []
    scan = Scan(id="scan_queue_unit", mode=ScanMode.url, target_url="https://example.com")

    class FakeStore:
        def get_scan(self, scan_id, owner_user_id=None):
            assert scan_id == scan.id
            return scan

        def save_scan(self, updated, owner_user_id=None):
            saved_statuses.append(updated.status)
            return updated

    async def fake_cancelled(settings, scan_id):
        return False

    async def fake_url_scan(updated, settings, progress_callback=None, cancellation_checker=None):
        updated.status = "completed"
        if progress_callback:
            await progress_callback(updated)
        return updated

    monkeypatch.setattr("nope_api.queue.store", FakeStore())
    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", fake_cancelled)
    monkeypatch.setattr("nope_api.queue.run_url_only_scan", fake_url_scan)

    await execute_scan_job(
        Settings(),
        {"scan_id": scan.id, "owner_user_id": None, "mode": "url"},
    )

    assert saved_statuses == ["running", "completed", "completed"]
    assert scan.stages[0]["name"] == "Worker picked up scan"


@pytest.mark.asyncio
async def test_execute_scan_job_persists_cancelled_scan(monkeypatch):
    saved_statuses: list[str] = []
    scan = Scan(id="scan_queue_cancel", mode=ScanMode.url, target_url="https://example.com")

    class FakeStore:
        def get_scan(self, scan_id, owner_user_id=None):
            return scan

        def save_scan(self, updated, owner_user_id=None):
            saved_statuses.append(updated.status)
            return updated

    async def fake_cancelled(settings, scan_id):
        return True

    monkeypatch.setattr("nope_api.queue.store", FakeStore())
    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", fake_cancelled)

    await execute_scan_job(Settings(), {"scan_id": scan.id, "owner_user_id": None, "mode": "url"})

    assert saved_statuses == ["cancelled"]
    assert scan.status == "cancelled"
    assert scan.stages[-1]["status"] == "cancelled"


@pytest.mark.asyncio
async def test_job_failure_requeues_with_bounded_retry(monkeypatch):
    scan = Scan(id="scan_queue_retry", mode=ScanMode.url, target_url="https://example.com")
    pushed: list[str] = []

    class FakeStore:
        def get_scan(self, scan_id, owner_user_id=None):
            return scan

        def save_scan(self, updated, owner_user_id=None):
            return updated

    class FakeRedis:
        async def hset(self, *args, **kwargs):
            return 1

        async def rpush(self, key, payload):
            pushed.append(payload)
            return len(pushed)

        async def delete(self, key):
            return 1

    async def fake_cancelled(settings, scan_id):
        return False

    monkeypatch.setattr("nope_api.queue.store", FakeStore())
    monkeypatch.setattr("nope_api.queue.is_scan_cancelled", fake_cancelled)

    await _handle_job_failure(
        Settings(),
        FakeRedis(),
        {"scan_id": scan.id, "owner_user_id": None, "mode": "url", "job_id": "job_1", "attempt": 1, "max_attempts": 2},
        RuntimeError("scanner died with api_key=sk-test-secret-value"),
    )

    assert pushed
    assert scan.status == "queued"
    assert scan.stages[-2]["status"] == "failed"
    assert "***REDACTED***" in scan.stages[-2]["message"]
    assert scan.stages[-1]["name"] == "Retry queued"


@pytest.mark.asyncio
async def test_scan_events_report_persisted_progress():
    scan = Scan(id="scan_events", mode=ScanMode.url, status="running")
    scan.stages.append({"name": "Queued", "status": "completed"})
    scan.stages.append({"name": "Running", "status": "running"})

    payload = await scan_events(scan)

    assert payload["scan_id"] == scan.id
    assert payload["status"] == "running"
    assert payload["progress"] == 50
    assert payload["stages"] == scan.stages
