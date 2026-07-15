from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from nope_api import __version__
from nope_api.ai import check_ai_health, explain_finding, finding_action
from nope_api.auth import create_or_login, delete_session, get_user_for_token, init_auth_db
from nope_api.config import get_settings
from nope_api.db import migration_status, run_migrations
from nope_api.drift import BaselineSnapshot, baseline_snapshot, compare_scans
from nope_api.findings import finding_detail, parse_finding_query, query_findings, raw_artifact
from nope_api.ingestion import extract_zip
from nope_api.models import AuthorizationScope, Project, Scan, ScanMode, ScanRequest
from nope_api.queue import clear_scan_cancel, enqueue_scan_job, queue_status, request_scan_cancel, scan_events
from nope_api.reports import ReportContext, render_report
from nope_api.sandbox import sandbox_health
from nope_api.scanners import scanner_capabilities, scanner_health
from nope_api.security import validate_url_scope
from nope_api.storage import store

settings = get_settings()

app = FastAPI(
    title="NOPE API",
    description="Rules-first application security orchestration API.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.web_url, "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    run_migrations(settings)
    store.backfill_report_bodies()


@app.get("/health")
async def health() -> dict:
    production_warnings = settings.validate_production_secrets()
    ai_health = await check_ai_health(settings)
    return {
        "status": "ok" if not production_warnings else "degraded",
        "version": __version__,
        "environment": settings.environment,
        "database": migration_status(settings),
        "scanners": scanner_health(),
        "ai": {
            "provider": settings.ai_provider,
            "runtime_url": settings.qwen_runtime_url,
            "model": settings.ai_model_name,
            "model_path": settings.qwen_model_path,
            "gpu_layers": settings.effective_qwen_gpu_layers,
            "gpu_memory_target_mb": settings.effective_qwen_gpu_memory_target_mb,
            "health": ai_health,
        },
        "sandbox": sandbox_health(settings),
        "warnings": production_warnings,
    }


@app.get("/api/projects", response_model=list[Project])
def list_projects(authorization: str | None = Header(default=None)) -> list[Project]:
    return store.list_projects(_require_owner_user_id(authorization))


@app.post("/api/auth/login")
def login(payload: dict) -> dict:
    try:
        return create_or_login(settings, str(payload.get("email", "")), str(payload.get("password", "")))
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/auth/me")
def me(authorization: str | None = Header(default=None)) -> dict:
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    user = get_user_for_token(settings, token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {"user": user}


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(default=None)) -> dict:
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    delete_session(settings, token)
    return {"ok": True}


def _owner_user_id(authorization: str | None) -> str | None:
    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    if not token:
        return None
    user = get_user_for_token(settings, token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return str(user["id"])


def _require_owner_user_id(authorization: str | None) -> str | None:
    owner_user_id = _owner_user_id(authorization)
    if not owner_user_id and settings.require_authenticated_api:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return owner_user_id


def _load_scan(scan_id: str, authorization: str | None) -> Scan:
    scan = store.get_scan(scan_id, _require_owner_user_id(authorization))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def _comparison_reference(
    current: Scan,
    owner_user_id: str | None,
    authorization: str | None,
    against_scan_id: str | None,
    baseline_id: str | None,
) -> Scan | BaselineSnapshot:
    if baseline_id:
        baseline = store.get_security_baseline(baseline_id, owner_user_id)
        if not baseline:
            raise HTTPException(status_code=404, detail="Baseline not found.")
        return BaselineSnapshot(**baseline["data"])
    if against_scan_id:
        return _load_scan(against_scan_id, authorization)
    candidates = [
        scan
        for scan in store.list_scans(owner_user_id)
        if scan.id != current.id and (not current.project_id or scan.project_id == current.project_id)
    ]
    if not candidates:
        raise HTTPException(status_code=409, detail="No previous scan or baseline is available for comparison.")
    return candidates[0]


@app.post("/api/projects", response_model=Project)
def create_project(project: Project, authorization: str | None = Header(default=None)) -> Project:
    return store.create_project(
        project.name,
        project.repository,
        project.target_url,
        _require_owner_user_id(authorization),
    )


@app.get("/api/scans", response_model=list[Scan])
def list_scans(authorization: str | None = Header(default=None)) -> list[Scan]:
    return store.list_scans(_require_owner_user_id(authorization))


@app.get("/api/scanners/capabilities")
def scanners_capabilities(authorization: str | None = Header(default=None)) -> list[dict]:
    _require_owner_user_id(authorization)
    return scanner_capabilities()


@app.get("/api/sandbox/health")
def get_sandbox_health(authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    return sandbox_health(settings)


@app.get("/api/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str, authorization: str | None = Header(default=None)) -> Scan:
    return _load_scan(scan_id, authorization)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    authorization: str | None = Header(default=None),
    severity: str | None = None,
    confidence: str | None = None,
    status: str | None = None,
    scanner: str | None = None,
    rule: str | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    file: str | None = None,
    route: str | None = None,
    first_seen: str | None = None,
    new: str | None = None,
    fixed: str | None = None,
    reintroduced: str | None = None,
    suppressed: str | None = None,
    ai_reviewed: str | None = None,
    verified: str | None = None,
    fix_available: str | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = 25,
    sort: str = "severity",
    direction: str = "asc",
):
    scan = _load_scan(scan_id, authorization)
    parsed = parse_finding_query(
        severity=severity,
        confidence=confidence,
        status=status,
        scanner=scanner,
        rule=rule,
        cwe=cwe,
        owasp=owasp,
        file=file,
        route=route,
        first_seen=first_seen,
        new=new,
        fixed=fixed,
        reintroduced=reintroduced,
        suppressed=suppressed,
        ai_reviewed=ai_reviewed,
        verified=verified,
        fix_available=fix_available,
        query=query,
        page=page,
        page_size=page_size,
        sort=sort,
        direction=direction,
    )
    return query_findings(scan, parsed)


@app.get("/api/scans/{scan_id}/findings/{finding_id}")
def get_finding_detail(scan_id: str, finding_id: str, authorization: str | None = Header(default=None)):
    detail = finding_detail(_load_scan(scan_id, authorization), finding_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return detail


@app.post("/api/scans/{scan_id}/findings/{finding_id}/suppress", response_model=Scan)
def suppress_finding(scan_id: str, finding_id: str, payload: dict, authorization: str | None = Header(default=None)) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    scan = _load_scan(scan_id, authorization)
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    from nope_api.models import Suppression

    expiry = payload.get("expiry")
    finding.suppression = Suppression(
        reason=str(payload.get("reason") or "Suppressed from findings detail."),
        user=str(payload.get("user") or owner_user_id or "local-user"),
        expiry=datetime.fromisoformat(expiry) if expiry else None,
        scope=str(payload.get("scope") or "finding"),
    )
    finding.status = "suppressed"
    return store.save_scan(scan, owner_user_id)


@app.get("/api/scans/{scan_id}/artifacts/{artifact_id}")
def get_raw_artifact(scan_id: str, artifact_id: str, authorization: str | None = Header(default=None)):
    artifact = raw_artifact(_load_scan(scan_id, authorization), artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return artifact


@app.get("/api/scans/{scan_id}/coverage")
def get_coverage(scan_id: str, authorization: str | None = Header(default=None)):
    return _load_scan(scan_id, authorization).coverage


@app.post("/api/scans/{scan_id}/baseline")
def create_scan_baseline(scan_id: str, payload: dict | None = None, authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    scan = _load_scan(scan_id, authorization)
    snapshot = baseline_snapshot(scan)
    baseline = store.create_security_baseline(
        scan.project_id,
        scan.id,
        str((payload or {}).get("name") or f"Baseline for {scan.id}"),
        snapshot.model_dump(mode="json"),
    )
    return baseline


@app.get("/api/baselines")
def list_baselines(project_id: str | None = None, authorization: str | None = Header(default=None)):
    return store.list_security_baselines(_require_owner_user_id(authorization), project_id)


@app.get("/api/baselines/{baseline_id}")
def get_baseline(baseline_id: str, authorization: str | None = Header(default=None)):
    baseline = store.get_security_baseline(baseline_id, _require_owner_user_id(authorization))
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found.")
    return baseline


@app.get("/api/scans/{scan_id}/compare")
def compare_scan(
    scan_id: str,
    against_scan_id: str | None = None,
    baseline_id: str | None = None,
    authorization: str | None = Header(default=None),
):
    owner_user_id = _require_owner_user_id(authorization)
    current = _load_scan(scan_id, authorization)
    reference = _comparison_reference(current, owner_user_id, authorization, against_scan_id, baseline_id)
    return compare_scans(current, reference, baseline_id=baseline_id)


@app.post("/api/scans/{scan_id}/drift")
def record_scan_drift(
    scan_id: str,
    against_scan_id: str | None = None,
    baseline_id: str | None = None,
    authorization: str | None = Header(default=None),
):
    owner_user_id = _require_owner_user_id(authorization)
    current = _load_scan(scan_id, authorization)
    reference = _comparison_reference(current, owner_user_id, authorization, against_scan_id, baseline_id)
    comparison = compare_scans(current, reference, baseline_id=baseline_id)
    persisted = []
    for event in comparison.drift_events:
        persisted.append(
            store.create_drift_event(
                baseline_id,
                current.id,
                event.type,
                event.message,
                event.severity,
                event.model_dump(mode="json"),
            )
        )
    return {"comparison": comparison, "persisted_events": persisted}


@app.get("/api/scans/{scan_id}/drift")
def list_scan_drift(scan_id: str, authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    _load_scan(scan_id, authorization)
    return store.list_drift_events(scan_id, owner_user_id)


@app.get("/api/scans/{scan_id}/events")
async def get_scan_events(scan_id: str, authorization: str | None = Header(default=None)) -> dict:
    return await scan_events(_load_scan(scan_id, authorization))


@app.get("/api/scans/{scan_id}/attack-map")
def get_attack_map(scan_id: str, authorization: str | None = Header(default=None)):
    scan = _load_scan(scan_id, authorization)
    return {"attack_surface": scan.attack_surface, "code_graph": scan.code_graph}


@app.get("/api/scans/{scan_id}/report.{fmt}")
def get_report(scan_id: str, fmt: str, authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    scan = _load_scan(scan_id, authorization)
    try:
        if fmt == "pdf":
            context = ReportContext(
                drift_events=store.list_drift_events(scan_id, owner_user_id),
                baselines=store.list_security_baselines(owner_user_id, scan.project_id),
            )
            media_type, body = render_report(scan, fmt, context)
            store.save_report(scan, fmt, media_type, body, owner_user_id=owner_user_id)
        else:
            stored_report = store.get_report(scan_id, fmt, owner_user_id)
            if stored_report:
                media_type, body = stored_report
            else:
                media_type, body = render_report(scan, fmt)
                store.save_report(scan, fmt, media_type, body, owner_user_id=owner_user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    filename = f"nope-{scan.id}.{fmt}"
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/{scan_id}/reports/{fmt}/status")
def get_report_status(scan_id: str, fmt: str, authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    _load_scan(scan_id, authorization)
    status = store.get_report_status(scan_id, fmt, owner_user_id)
    if not status:
        return {"scan_id": scan_id, "format": fmt, "status": "not_generated"}
    return status


@app.post("/api/scans/url", response_model=Scan)
async def start_url_scan(request: ScanRequest, authorization: str | None = Header(default=None)) -> Scan:
    if request.mode != ScanMode.url:
        raise HTTPException(status_code=400, detail="Use mode=url for this endpoint.")
    if not request.target_url:
        raise HTTPException(status_code=400, detail="target_url is required.")
    owner_user_id = _require_owner_user_id(authorization)
    scope = validate_url_scope(str(request.target_url), request.authorization, settings)
    if scope.confirmed_at is None:
        scope.confirmed_at = datetime.now(timezone.utc)
    scan = Scan(
        project_id=request.project_id,
        mode=ScanMode.url,
        target_url=str(request.target_url),
        status="queued",
        stages=[{"name": "Queued for worker", "status": "queued"}],
    )
    store.save_scan(scan, owner_user_id)
    await enqueue_scan_job(settings, {"scan_id": scan.id, "owner_user_id": owner_user_id, "mode": scan.mode.value})
    return scan


@app.post("/api/scans/repository", response_model=Scan)
async def start_repository_scan(
    file: UploadFile = File(...),
    project_id: str | None = Form(default=None),
    repository_name: str | None = Form(default="Uploaded ZIP"),
    branch: str | None = Form(default=None),
    commit_sha: str | None = Form(default=None),
    authorization: str | None = Header(default=None),
) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    scan = Scan(
        project_id=project_id,
        mode=ScanMode.repository,
        repository_name=repository_name,
        status="preparing",
        branch=branch,
        commit_sha=commit_sha,
    )
    store.save_scan(scan, owner_user_id)
    root = await extract_zip(file, scan.id, settings)
    scan.repository_workspace_path = str(root)
    scan.status = "queued"
    scan.stages.append({"name": "Queued for worker", "status": "queued", "message": "Repository extracted and ready."})
    store.save_scan(scan, owner_user_id)
    await enqueue_scan_job(
        settings,
        {
            "scan_id": scan.id,
            "owner_user_id": owner_user_id,
            "mode": scan.mode.value,
            "repository_workspace_path": scan.repository_workspace_path,
        },
    )
    return scan


@app.post("/api/scans/full", response_model=Scan)
async def start_full_scan(
    file: UploadFile = File(...),
    target_url: str = Form(...),
    authorization_confirmed: bool = Form(False),
    approved_hosts: str | None = Form(default=None),
    project_id: str | None = Form(default=None),
    repository_name: str | None = Form(default="Uploaded ZIP"),
    branch: str | None = Form(default=None),
    commit_sha: str | None = Form(default=None),
    authorization: str | None = Header(default=None),
) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    scope = AuthorizationScope(
        confirmed=authorization_confirmed,
        confirmed_at=datetime.now(timezone.utc) if authorization_confirmed else None,
        approved_hosts=[host.strip() for host in (approved_hosts or "").split(",") if host.strip()],
    )
    validate_url_scope(target_url, scope, settings)
    scan = Scan(
        project_id=project_id,
        mode=ScanMode.full,
        target_url=target_url,
        repository_name=repository_name,
        status="preparing",
        branch=branch,
        commit_sha=commit_sha,
    )
    store.save_scan(scan, owner_user_id)
    root = await extract_zip(file, scan.id, settings)
    scan.repository_workspace_path = str(root)
    scan.status = "queued"
    scan.stages.append({"name": "Queued for worker", "status": "queued", "message": "Repository extracted and URL scope confirmed."})
    store.save_scan(scan, owner_user_id)
    await enqueue_scan_job(
        settings,
        {
            "scan_id": scan.id,
            "owner_user_id": owner_user_id,
            "mode": scan.mode.value,
            "repository_workspace_path": scan.repository_workspace_path,
        },
    )
    return scan


@app.post("/api/scans/{scan_id}/cancel", response_model=Scan)
async def cancel_scan(scan_id: str, authorization: str | None = Header(default=None)) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    scan = _load_scan(scan_id, authorization)
    await request_scan_cancel(settings, scan_id)
    if scan.status in {"queued", "preparing"}:
        scan.status = "cancelled"
        scan.completed_at = datetime.now(timezone.utc)
    scan.stages.append({"name": "Cancellation requested", "status": "cancelled"})
    return store.save_scan(scan, owner_user_id)


@app.post("/api/scans/{scan_id}/retry", response_model=Scan)
async def retry_scan(scan_id: str, authorization: str | None = Header(default=None)) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    scan = _load_scan(scan_id, authorization)
    if scan.status in {"queued", "preparing", "running"}:
        raise HTTPException(status_code=409, detail="Scan is already active.")
    if scan.mode in {ScanMode.repository, ScanMode.full} and not scan.repository_workspace_path:
        raise HTTPException(status_code=409, detail="Repository workspace is not available for retry.")
    scan.status = "queued"
    scan.completed_at = None
    scan.stages.append({"name": "Retry queued", "status": "queued"})
    store.save_scan(scan, owner_user_id)
    await clear_scan_cancel(settings, scan.id)
    job = {"scan_id": scan.id, "owner_user_id": owner_user_id, "mode": scan.mode.value}
    if scan.repository_workspace_path:
        job["repository_workspace_path"] = scan.repository_workspace_path
    await enqueue_scan_job(settings, job, force=True)
    return scan


@app.get("/api/queue/status")
async def get_queue_status(authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    return await queue_status(settings)


@app.get("/api/worker/health")
async def get_worker_health(authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    status = await queue_status(settings)
    return {
        "status": "ok" if status.get("redis") == "ok" and status.get("worker_healthy") else "degraded",
        **status,
    }


@app.get("/api/settings/model")
def model_settings(authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    return {
        "provider": settings.ai_provider,
        "model_name": settings.ai_model_name,
        "model_file_path": settings.qwen_model_path,
        "runtime_endpoint": settings.qwen_runtime_url,
        "context_length": settings.effective_qwen_context_size,
        "maximum_output_tokens": settings.effective_qwen_max_output_tokens,
        "temperature": settings.ai_temperature,
        "top_p": settings.ai_top_p,
        "gpu_layer_count": settings.effective_qwen_gpu_layers,
        "maximum_gpu_memory_target_mb": settings.effective_qwen_gpu_memory_target_mb,
        "batch_size": settings.qwen_batch_size,
        "threads": settings.qwen_threads,
        "parallel": settings.qwen_parallel,
        "request_timeout": settings.effective_qwen_timeout_seconds,
        "maximum_concurrent_ai_tasks": settings.ai_max_concurrent_tasks,
        "maximum_analysis_iterations": settings.ai_max_iterations,
        "maximum_tool_calls": settings.ai_max_tool_calls,
        "maximum_retrieved_chunks": settings.ai_max_retrieved_chunks,
        "maximum_repository_tokens_per_task": settings.ai_max_repository_tokens,
        "rag": {
            "maximum_files": settings.ai_rag_max_files,
            "maximum_tokens": settings.ai_rag_max_tokens,
            "maximum_graph_depth": settings.ai_rag_graph_depth,
            "chunk_characters": settings.ai_rag_chunk_chars,
            "embeddings_required": False,
        },
    }


@app.post("/api/settings/model/test")
async def test_model(authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    health_result = await check_ai_health(settings)
    status = "Complete" if health_result["status"] == "ok" else "Failed"
    if health_result["status"] == "disabled":
        status = "Not tested"
    return {"status": status, **health_result}


@app.post("/api/findings/explain")
async def explain_finding_endpoint(finding: dict, authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    from nope_api.models import Finding

    parsed = Finding(**finding)
    return await explain_finding(settings, parsed)


@app.post("/api/findings/{action}")
async def finding_action_endpoint(action: str, finding: dict, authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    if action not in {"explain", "challenge", "fix", "test"}:
        raise HTTPException(status_code=404, detail="Unsupported finding AI action.")
    from nope_api.models import Finding

    parsed = Finding(**finding)
    return await finding_action(settings, parsed, action)  # type: ignore[arg-type]
