from __future__ import annotations

import asyncio
import json
import socket
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
WORKER_IDENTITY = socket.gethostname() or "nope-worker"


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


async def scan_events(scan: Scan, owner_user_id: str | None = None, *, after_sequence: int | None = None, limit: int = 100) -> dict[str, Any]:
    persisted = store.list_scan_events(scan.id, owner_user_id, after_sequence=after_sequence, limit=limit)
    if persisted and persisted["total"] == 0:
        store.backfill_scan_events_from_snapshot(scan, owner_user_id)
        persisted = store.list_scan_events(scan.id, owner_user_id, after_sequence=after_sequence, limit=limit)
    if persisted and persisted["events"]:
        latest_progress = next(
            (event.get("progress") for event in reversed(persisted["events"]) if event.get("progress") is not None),
            _progress_percent(scan),
        )
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "progress": latest_progress,
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
            **persisted,
        }
    if persisted and persisted["total"] > 0:
        latest = store.list_scan_events(scan.id, owner_user_id, limit=1_000_000)
        latest_progress = next(
            (event.get("progress") for event in reversed(latest["events"]) if event.get("progress") is not None),
            _progress_percent(scan),
        ) if latest else _progress_percent(scan)
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "progress": latest_progress,
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
            **persisted,
        }
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


def _scan_event_type(status: str) -> str:
    return {
        "queued": "scan_queued",
        "preparing": "scan_preparing",
        "running": "scan_started",
        "completed": "scan_completed",
        "partial": "scan_partial",
        "failed": "scan_failed",
        "cancelled": "scan_cancelled",
    }.get(status, "stage_progress")


def _stage_event_type(status: str) -> str:
    return {
        "queued": "stage_queued",
        "running": "stage_started",
        "completed": "stage_completed",
        "partial": "stage_partial",
        "failed": "stage_failed",
        "skipped": "stage_skipped",
        "cancelled": "scan_cancelled",
        "timed out": "stage_failed",
        "timed_out": "stage_failed",
    }.get(status, "stage_progress")


def _scanner_event_type(status: str, message: str = "") -> str:
    lowered = (message or "").lower()
    if "timeout" in lowered or status == "timed_out":
        return "scanner_timed_out"
    if "unavailable" in lowered or status == "skipped":
        return "scanner_unavailable"
    if status == "failed":
        return "scanner_failed"
    return "scanner_completed"


def _persist_event_snapshot(scan: Scan, owner_user_id: str | None, *, attempt: int = 1, job_id: str | None = None) -> None:
    progress = _progress_percent(scan)
    store.record_scan_event(
        scan.id,
        _scan_event_type(scan.status),
        owner_user_id=owner_user_id,
        new_state=scan.status,
        progress=progress,
        message=scan.verdict if scan.status in {"completed", "partial", "failed", "cancelled"} else f"Scan is {scan.status}.",
        attempt=attempt,
        worker_identity=WORKER_IDENTITY,
        metadata={"job_id": job_id} if job_id else {},
        idempotency_key=f"scan:{scan.status}:attempt:{attempt}",
    )
    for index, stage in enumerate(scan.stages):
        status = str(stage.get("status") or "running")
        stage_name = str(stage.get("name") or "")
        event_type = "qwen_started" if "qwen" in stage_name.lower() and status == "running" else _stage_event_type(status)
        store.record_scan_event(
            scan.id,
            event_type,
            owner_user_id=owner_user_id,
            stage_id=f"stage:{index}",
            new_state=status,
            progress=progress,
            message=str(stage.get("message") or stage.get("name") or ""),
            metadata={"stage": stage, "index": index},
            attempt=int(stage.get("attempt") or attempt),
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"stage:{index}:{status}:attempt:{int(stage.get('attempt') or attempt)}",
        )
        if status == "running":
            store.record_scan_event(
                scan.id,
                "stage_progress",
                owner_user_id=owner_user_id,
                stage_id=f"stage:{index}",
                new_state=status,
                progress=progress,
                message=str(stage.get("message") or stage.get("name") or ""),
                metadata={"stage": stage, "index": index},
                attempt=int(stage.get("attempt") or attempt),
                worker_identity=WORKER_IDENTITY,
                idempotency_key=f"stage:{index}:progress:attempt:{int(stage.get('attempt') or attempt)}",
            )
    for index, run in enumerate(scan.scanner_runs):
        scanner_id = f"scanner:{index}:{run.scanner}"
        store.record_scan_event(
            scan.id,
            "scanner_started",
            owner_user_id=owner_user_id,
            scanner_run_id=scanner_id,
            new_state="running",
            progress=progress,
            message=f"{run.scanner} started.",
            metadata={"scanner": run.scanner},
            attempt=attempt,
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"scanner:{index}:{run.scanner}:started:attempt:{attempt}",
        )
        terminal_type = _scanner_event_type(run.status, run.message)
        store.record_scan_event(
            scan.id,
            terminal_type,
            owner_user_id=owner_user_id,
            scanner_run_id=scanner_id,
            new_state=run.status,
            progress=progress,
            message=run.message or f"{run.scanner} {run.status}.",
            metadata={"scanner": run.model_dump(mode="json")},
            error_code=run.status if run.status != "passed" else None,
            error_details=run.message if run.status != "passed" else None,
            attempt=attempt,
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"scanner:{index}:{run.scanner}:{run.status}:attempt:{attempt}",
        )
    if scan.ai_review.status != "Not tested":
        qwen_type = "qwen_completed" if scan.ai_review.status in {"Complete", "Partial"} else "qwen_failed"
        store.record_scan_event(
            scan.id,
            qwen_type,
            owner_user_id=owner_user_id,
            new_state=scan.ai_review.status,
            progress=progress,
            message=scan.ai_review.message,
            metadata={"ai_review": scan.ai_review.model_dump(mode="json")},
            error_code="qwen_failed" if qwen_type == "qwen_failed" else None,
            error_details=scan.ai_review.message if qwen_type == "qwen_failed" else None,
            attempt=attempt,
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"qwen:{scan.ai_review.status}:attempt:{attempt}",
        )
    if scan.status in {"completed", "partial", "failed", "cancelled"}:
        for fmt in scan.report_formats:
            store.record_scan_event(
                scan.id,
                "report_started",
                owner_user_id=owner_user_id,
                new_state="running",
                progress=progress,
                message=f"{fmt.upper()} report generation started.",
                metadata={"format": fmt},
                attempt=attempt,
                worker_identity=WORKER_IDENTITY,
                idempotency_key=f"report:{fmt}:started:attempt:{attempt}",
            )
            store.record_scan_event(
                scan.id,
                "report_completed",
                owner_user_id=owner_user_id,
                new_state="completed",
                progress=progress,
                message=f"{fmt.upper()} report generation completed.",
                metadata={"format": fmt},
                attempt=attempt,
                worker_identity=WORKER_IDENTITY,
                idempotency_key=f"report:{fmt}:completed:attempt:{attempt}",
            )


def _progress_percent(scan: Scan) -> int:
    if scan.status in {"completed", "failed", "cancelled", "partial"}:
        return 100
    if scan.status == "preparing":
        return 3
    if scan.status == "queued":
        return 0
    if not scan.stages:
        return 15 if scan.status == "running" else 0
    done = sum(1 for stage in scan.stages if stage.get("status") in {"completed", "partial", "failed", "skipped", "cancelled", "timed out"})
    floor = 15 if scan.status == "running" else 0
    expected_stages = len(scan.stages) if len(scan.stages) > 1 else 8
    return max(floor, min(99, round(done / expected_stages * 100)))


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
            scan = store.get_scan(str(job.get("scan_id")), job.get("owner_user_id"))
            if scan:
                store.record_scan_event(
                    scan.id,
                    "worker_heartbeat",
                    owner_user_id=job.get("owner_user_id"),
                    new_state="running",
                    progress=_progress_percent(scan),
                    message="Worker heartbeat recorded for active scan.",
                    metadata={"job_id": job.get("job_id"), "started_at": job.get("started_at")},
                    attempt=int(job.get("attempt", 1)),
                    worker_identity=WORKER_IDENTITY,
                    idempotency_key=f"worker_heartbeat:{job.get('job_id')}:{job.get('attempt')}",
                )
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
        _persist_event_snapshot(scan, owner_user_id, attempt=int(job.get("attempt", 1)), job_id=job.get("job_id"))
        return

    async def persist_progress(updated: Scan) -> None:
        store.save_scan(updated, owner_user_id)
        _persist_event_snapshot(updated, owner_user_id, attempt=int(job.get("attempt", 1)), job_id=job.get("job_id"))

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
        store.record_scan_event(
            scan.id,
            "retry_started" if int(job.get("attempt", 1)) > 1 else "scan_started",
            owner_user_id=owner_user_id,
            previous_state="queued",
            new_state="running",
            progress=_progress_percent(scan),
            message="Redis job accepted.",
            metadata={"job_id": job.get("job_id")},
            attempt=int(job.get("attempt", 1)),
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"scan:started:attempt:{int(job.get('attempt', 1))}",
        )
        _persist_event_snapshot(scan, owner_user_id, attempt=int(job.get("attempt", 1)), job_id=job.get("job_id"))

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
        _persist_event_snapshot(completed, owner_user_id, attempt=int(job.get("attempt", 1)), job_id=job.get("job_id"))
    except ScanCancelled:
        scan.status = "cancelled"
        scan.completed_at = now_utc()
        store.save_scan(scan, owner_user_id)
        _persist_event_snapshot(scan, owner_user_id, attempt=int(job.get("attempt", 1)), job_id=job.get("job_id"))
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = now_utc()
        _append_stage(scan, "Worker execution failed", "failed", str(exc), attempt=job.get("attempt", 1))
        store.save_scan(scan, owner_user_id)
        store.record_scan_event(
            scan.id,
            "scan_failed",
            owner_user_id=owner_user_id,
            previous_state="running",
            new_state="failed",
            progress=100,
            message="Worker execution failed.",
            error_code=exc.__class__.__name__,
            error_details=str(exc),
            attempt=int(job.get("attempt", 1)),
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"scan:failed:attempt:{int(job.get('attempt', 1))}:{exc.__class__.__name__}",
        )
        _persist_event_snapshot(scan, owner_user_id, attempt=int(job.get("attempt", 1)), job_id=job.get("job_id"))
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
        store.record_scan_event(
            scan.id,
            "scanner_timed_out" if timed_out else "scan_failed",
            owner_user_id=owner_user_id,
            previous_state="running",
            new_state=scan.status,
            progress=100,
            message=message,
            error_code="whole_scan_timeout" if timed_out else exc.__class__.__name__,
            error_details=message,
            attempt=attempt,
            worker_identity=WORKER_IDENTITY,
            idempotency_key=f"failure:{attempt}:{'timeout' if timed_out else exc.__class__.__name__}",
        )
        _persist_event_snapshot(scan, owner_user_id, attempt=attempt, job_id=job.get("job_id"))
    if attempt < max_attempts and not await is_scan_cancelled(settings, scan_id):
        retry_job = {**job, "attempt": attempt + 1}
        await _mark_job(redis, retry_job, "queued")
        await redis.rpush(QUEUE_KEY, _json({**retry_job, "run_after": _now() + _backoff(attempt)}))
        if scan:
            scan.status = "queued"
            scan.completed_at = None
            _append_stage(scan, "Retry queued", "queued", f"Retry {attempt + 1} of {max_attempts} queued.", attempt=attempt + 1)
            store.save_scan(scan, owner_user_id)
            store.record_scan_event(
                scan.id,
                "retry_scheduled",
                owner_user_id=owner_user_id,
                previous_state="failed",
                new_state="queued",
                progress=0,
                message=f"Retry {attempt + 1} of {max_attempts} queued.",
                metadata={"run_after": retry_job.get("run_after"), "job_id": retry_job.get("job_id")},
                attempt=attempt + 1,
                worker_identity=WORKER_IDENTITY,
                idempotency_key=f"retry:scheduled:{attempt + 1}",
            )
            _persist_event_snapshot(scan, owner_user_id, attempt=attempt + 1, job_id=job.get("job_id"))
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
        scan_id = str(job.get("scan_id"))
        owner_user_id = job.get("owner_user_id")
        scan = store.get_scan(scan_id, owner_user_id)
        if scan:
            store.record_scan_event(
                scan.id,
                "worker_lost",
                owner_user_id=owner_user_id,
                previous_state="running",
                new_state="queued",
                progress=_progress_percent(scan),
                message="Processing job exceeded stale-worker threshold and was requeued.",
                metadata={"started_at": started, "job_id": job.get("job_id")},
                attempt=int(job.get("attempt", 1)),
                worker_identity=WORKER_IDENTITY,
                idempotency_key=f"worker_lost:{job.get('job_id')}:{job.get('attempt')}",
            )
        requeued += 1
    return requeued
