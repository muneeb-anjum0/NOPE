from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from nope_api.config import Settings
from nope_api.models import Scan, ScanMode, new_id, now_utc
from nope_api.scan_engine import ScanCancelled, run_full_scan, run_repository_scan, run_url_only_scan
from nope_api.scanners import _bounded_redacted
from nope_api.storage import store

QUEUE_KEY = "nope:scan-jobs"
PROCESSING_KEY = "nope:scan-jobs:processing"
JOB_PREFIX = "nope:scan-job:"
ACTIVE_PREFIX = "nope:scan-active:"
CANCEL_PREFIX = "nope:scan-cancel:"
WORKER_HEARTBEAT_KEY = "nope:worker:heartbeat"
MAX_ATTEMPTS = 3
MAX_BACKOFF_SECONDS = 30
STUCK_AFTER_SECONDS = 10 * 60


def _redis_error() -> RuntimeError:
    return RuntimeError("Redis queue support requires the redis Python package.")


async def _client(settings: Settings):
    try:
        from redis.asyncio import Redis
    except ImportError as exc:  # pragma: no cover - dependency is present in Docker.
        raise _redis_error() from exc
    return Redis.from_url(settings.redis_url, decode_responses=True)


def _now() -> float:
    return time.time()


def _json(job: dict[str, Any]) -> str:
    return json.dumps(job, sort_keys=True)


def _job_key(job_id: str) -> str:
    return f"{JOB_PREFIX}{job_id}"


def _active_key(scan_id: str) -> str:
    return f"{ACTIVE_PREFIX}{scan_id}"


def _backoff(attempt: int) -> int:
    return min(MAX_BACKOFF_SECONDS, 2 ** max(0, attempt - 1))


def _job_from_payload(payload: str) -> dict[str, Any] | None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _event(name: str, status: str, message: str = "", **data: Any) -> dict[str, Any]:
    event = {"name": name, "status": status, "at": now_utc().isoformat()}
    if message:
        event["message"] = _bounded_redacted(message, 4096)
    event.update(data)
    return event


def _append_stage(scan: Scan, name: str, status: str, message: str = "", **data: Any) -> None:
    scan.stages.append(_event(name, status, message, **data))


async def enqueue_scan_job(
    settings: Settings,
    job: dict[str, Any],
    *,
    force: bool = False,
    delay_seconds: int = 0,
) -> dict[str, Any]:
    scan_id = str(job["scan_id"])
    redis = await _client(settings)
    try:
        active_key = _active_key(scan_id)
        if not force and not await redis.set(active_key, "1", nx=True, ex=settings.max_scan_seconds + 3600):
            depth = await redis.llen(QUEUE_KEY)
            return {"queued": False, "duplicate": True, "queue_depth": depth}

        job.setdefault("job_id", new_id("job"))
        job.setdefault("attempt", 1)
        job.setdefault("max_attempts", MAX_ATTEMPTS)
        job.setdefault("queued_at", now_utc().isoformat())
        job["run_after"] = _now() + max(0, delay_seconds)
        payload = _json(job)
        await redis.hset(
            _job_key(str(job["job_id"])),
            mapping={
                "scan_id": scan_id,
                "status": "queued",
                "attempt": str(job["attempt"]),
                "payload": payload,
                "updated_at": now_utc().isoformat(),
            },
        )
        await redis.rpush(QUEUE_KEY, payload)
        depth = await redis.llen(QUEUE_KEY)
        return {"queued": True, "job_id": job["job_id"], "queue_depth": depth}
    finally:
        await redis.aclose()


async def request_scan_cancel(settings: Settings, scan_id: str) -> None:
    redis = await _client(settings)
    try:
        await redis.set(f"{CANCEL_PREFIX}{scan_id}", "1", ex=24 * 60 * 60)
    finally:
        await redis.aclose()


async def clear_scan_cancel(settings: Settings, scan_id: str) -> None:
    redis = await _client(settings)
    try:
        await redis.delete(f"{CANCEL_PREFIX}{scan_id}")
    finally:
        await redis.aclose()


async def is_scan_cancelled(settings: Settings, scan_id: str) -> bool:
    redis = await _client(settings)
    try:
        return bool(await redis.exists(f"{CANCEL_PREFIX}{scan_id}"))
    finally:
        await redis.aclose()


async def queue_status(settings: Settings) -> dict[str, Any]:
    redis = await _client(settings)
    try:
        await _requeue_stuck_jobs(redis)
        heartbeat = await redis.get(WORKER_HEARTBEAT_KEY)
        processing = await redis.lrange(PROCESSING_KEY, 0, -1)
        return {
            "redis": "ok",
            "queue_depth": await redis.llen(QUEUE_KEY),
            "processing_depth": len(processing),
            "worker_heartbeat": heartbeat,
            "worker_healthy": bool(heartbeat),
            "processing_jobs": [
                {
                    "job_id": str(job.get("job_id")),
                    "scan_id": str(job.get("scan_id")),
                    "attempt": int(job.get("attempt", 1)),
                    "started_at": job.get("started_at"),
                }
                for job in (_job_from_payload(item) for item in processing)
                if job
            ],
        }
    except Exception as exc:
        return {"redis": "error", "message": _bounded_redacted(str(exc), 4096)}
    finally:
        await redis.aclose()


async def scan_events(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "progress": _progress_percent(scan),
        "stages": scan.stages,
        "scanner_runs": [
            {
                "scanner": run.scanner,
                "status": run.status,
                "findings_count": run.findings_count,
                "message": run.message,
            }
            for run in scan.scanner_runs
        ],
    }


def _progress_percent(scan: Scan) -> int:
    if scan.status in {"completed", "failed", "cancelled", "partial"}:
        return 100
    if not scan.stages:
        return 0
    done = sum(1 for stage in scan.stages if stage.get("status") in {"completed", "partial", "failed", "skipped", "cancelled", "timed out"})
    return min(99, round(done / max(1, len(scan.stages)) * 100))


async def worker_loop(settings: Settings) -> None:
    redis = await _client(settings)
    try:
        while True:
            await redis.set(WORKER_HEARTBEAT_KEY, now_utc().isoformat(), ex=60)
            await _requeue_stuck_jobs(redis)
            try:
                payload = await redis.brpoplpush(QUEUE_KEY, PROCESSING_KEY, timeout=5)
            except Exception as exc:
                if exc.__class__.__name__ != "TimeoutError":
                    raise
                await asyncio.sleep(1)
                continue
            if not payload:
                await asyncio.sleep(1)
                continue
            job = _job_from_payload(payload)
            if not job:
                await redis.lrem(PROCESSING_KEY, 1, payload)
                continue
            run_after = float(job.get("run_after") or 0)
            if run_after > _now():
                await redis.lrem(PROCESSING_KEY, 1, payload)
                await redis.rpush(QUEUE_KEY, payload)
                await asyncio.sleep(min(5, run_after - _now()))
                continue
            job["started_at"] = now_utc().isoformat()
            processing_payload = _json(job)
            if processing_payload != payload:
                await redis.lrem(PROCESSING_KEY, 1, payload)
                await redis.lpush(PROCESSING_KEY, processing_payload)
                payload = processing_payload
            await _mark_job(redis, job, "running")
            try:
                await asyncio.wait_for(execute_scan_job(settings, job), timeout=settings.max_scan_seconds)
                await _mark_job(redis, job, "completed")
                await redis.delete(_active_key(str(job["scan_id"])))
            except asyncio.TimeoutError as exc:
                await _handle_job_failure(settings, redis, job, exc, timed_out=True)
            except Exception as exc:
                await _handle_job_failure(settings, redis, job, exc)
            finally:
                await redis.lrem(PROCESSING_KEY, 1, payload)
    finally:
        await redis.aclose()


async def execute_scan_job(settings: Settings, job: dict[str, Any]) -> None:
    scan_id = str(job["scan_id"])
    owner_user_id = job.get("owner_user_id")
    scan = store.get_scan(scan_id, owner_user_id)
    if not scan:
        return
    if await is_scan_cancelled(settings, scan_id) or scan.status == "cancelled":
        scan.status = "cancelled"
        scan.completed_at = now_utc()
        _append_stage(scan, "Scan cancelled", "cancelled", "Cancelled before worker execution.")
        store.save_scan(scan, owner_user_id)
        return

    async def persist_progress(updated: Scan) -> None:
        store.save_scan(updated, owner_user_id)

    async def cancelled(updated: Scan) -> bool:
        return await is_scan_cancelled(settings, updated.id)

    try:
        scan.status = "running"
        _append_stage(
            scan,
            "Worker picked up scan",
            "completed",
            "Redis job accepted.",
            job_id=job.get("job_id"),
            attempt=job.get("attempt", 1),
        )
        store.save_scan(scan, owner_user_id)

        mode = ScanMode(str(job["mode"]))
        if mode == ScanMode.url:
            completed = await run_url_only_scan(scan, settings, persist_progress, cancelled)
        elif mode == ScanMode.repository:
            root = Path(str(job["repository_workspace_path"]))
            if not root.exists():
                raise FileNotFoundError(f"Repository workspace is missing: {root}")
            completed = await run_repository_scan(scan, root, settings, persist_progress, cancelled)
        else:
            root = Path(str(job["repository_workspace_path"]))
            if not root.exists():
                raise FileNotFoundError(f"Repository workspace is missing: {root}")
            completed = await run_full_scan(scan, root, settings, persist_progress, cancelled)

        if await is_scan_cancelled(settings, scan_id):
            completed.status = "cancelled"
            completed.completed_at = now_utc()
            _append_stage(completed, "Scan cancelled", "cancelled", "Cancelled after scan engine returned.")
        store.save_scan(completed, owner_user_id)
    except ScanCancelled:
        scan.status = "cancelled"
        scan.completed_at = now_utc()
        store.save_scan(scan, owner_user_id)
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = now_utc()
        _append_stage(scan, "Worker execution failed", "failed", str(exc), attempt=job.get("attempt", 1))
        store.save_scan(scan, owner_user_id)
        raise


async def _mark_job(redis, job: dict[str, Any], status: str) -> None:
    await redis.hset(
        _job_key(str(job.get("job_id"))),
        mapping={
            "scan_id": str(job.get("scan_id")),
            "status": status,
            "attempt": str(job.get("attempt", 1)),
            "payload": _json(job),
            "updated_at": now_utc().isoformat(),
        },
    )


async def _handle_job_failure(settings: Settings, redis, job: dict[str, Any], exc: BaseException, *, timed_out: bool = False) -> None:
    scan_id = str(job["scan_id"])
    owner_user_id = job.get("owner_user_id")
    scan = store.get_scan(scan_id, owner_user_id)
    attempt = int(job.get("attempt", 1))
    max_attempts = int(job.get("max_attempts", MAX_ATTEMPTS))
    message = "Whole-scan timeout exceeded." if timed_out else str(exc)
    if scan:
        scan.status = "partial" if scan.findings or scan.scanner_runs else "failed"
        scan.completed_at = now_utc()
        _append_stage(scan, "Worker attempt failed", "timed out" if timed_out else "failed", message, attempt=attempt)
        store.save_scan(scan, owner_user_id)
    if attempt < max_attempts and not await is_scan_cancelled(settings, scan_id):
        retry_job = {**job, "attempt": attempt + 1}
        await _mark_job(redis, retry_job, "queued")
        await redis.rpush(QUEUE_KEY, _json({**retry_job, "run_after": _now() + _backoff(attempt)}))
        if scan:
            scan.status = "queued"
            scan.completed_at = None
            _append_stage(scan, "Retry queued", "queued", f"Retry {attempt + 1} of {max_attempts} queued.", attempt=attempt + 1)
            store.save_scan(scan, owner_user_id)
    else:
        await _mark_job(redis, job, "failed")
        await redis.delete(_active_key(scan_id))


async def _requeue_stuck_jobs(redis) -> int:
    requeued = 0
    processing = await redis.lrange(PROCESSING_KEY, 0, -1)
    for payload in processing:
        job = _job_from_payload(payload)
        if not job:
            await redis.lrem(PROCESSING_KEY, 1, payload)
            continue
        started = job.get("started_at")
        if not started:
            continue
        try:
            started_epoch = datetime.fromisoformat(str(started)).timestamp()
        except ValueError:
            continue
        if _now() - started_epoch <= STUCK_AFTER_SECONDS:
            continue
        job.pop("started_at", None)
        job["attempt"] = int(job.get("attempt", 1)) + 1
        job["run_after"] = _now()
        await redis.lrem(PROCESSING_KEY, 1, payload)
        await redis.rpush(QUEUE_KEY, _json(job))
        await _mark_job(redis, job, "queued")
        requeued += 1
    return requeued
