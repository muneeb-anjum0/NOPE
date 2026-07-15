from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from nope_api import __version__
from nope_api.ai import check_ai_health, explain_finding
from nope_api.auth import create_or_login, delete_session, get_user_for_token, init_auth_db
from nope_api.config import get_settings
from nope_api.db import migration_status, run_migrations
from nope_api.ingestion import extract_zip
from nope_api.models import AuthorizationScope, Project, Scan, ScanMode, ScanRequest
from nope_api.reports import render_report
from nope_api.scan_engine import run_full_scan, run_repository_scan, run_url_only_scan
from nope_api.scanners import scanner_health
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
            "runtime_url": settings.ai_runtime_url,
            "model": settings.ai_model_name,
            "model_path": settings.ai_model_path,
            "gpu_layers": settings.ai_gpu_layers,
            "gpu_memory_target_mb": settings.ai_gpu_memory_target_mb,
            "health": ai_health,
        },
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


@app.get("/api/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str, authorization: str | None = Header(default=None)) -> Scan:
    return _load_scan(scan_id, authorization)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str, authorization: str | None = Header(default=None)):
    return _load_scan(scan_id, authorization).findings


@app.get("/api/scans/{scan_id}/coverage")
def get_coverage(scan_id: str, authorization: str | None = Header(default=None)):
    return _load_scan(scan_id, authorization).coverage


@app.get("/api/scans/{scan_id}/attack-map")
def get_attack_map(scan_id: str, authorization: str | None = Header(default=None)):
    scan = _load_scan(scan_id, authorization)
    return {"attack_surface": scan.attack_surface, "code_graph": scan.code_graph}


@app.get("/api/scans/{scan_id}/report.{fmt}")
def get_report(scan_id: str, fmt: str, authorization: str | None = Header(default=None)):
    scan = _load_scan(scan_id, authorization)
    try:
        stored_report = store.get_report(scan_id, fmt, _require_owner_user_id(authorization))
        media_type, body = stored_report or render_report(scan, fmt)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(content=body, media_type=media_type)


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
    )
    store.save_scan(scan, owner_user_id)
    scan = await run_url_only_scan(scan, settings)
    return store.save_scan(scan, owner_user_id)


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
        branch=branch,
        commit_sha=commit_sha,
    )
    store.save_scan(scan, owner_user_id)
    root = await extract_zip(file, scan.id, settings)
    scan = await run_repository_scan(scan, root, settings)
    return store.save_scan(scan, owner_user_id)


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
        branch=branch,
        commit_sha=commit_sha,
    )
    store.save_scan(scan, owner_user_id)
    root = await extract_zip(file, scan.id, settings)
    scan = await run_full_scan(scan, root, settings)
    return store.save_scan(scan, owner_user_id)


@app.get("/api/settings/model")
def model_settings(authorization: str | None = Header(default=None)) -> dict:
    _require_owner_user_id(authorization)
    return {
        "provider": settings.ai_provider,
        "model_name": settings.ai_model_name,
        "model_file_path": settings.ai_model_path,
        "runtime_endpoint": settings.ai_runtime_url,
        "context_length": settings.ai_context_length,
        "maximum_output_tokens": settings.ai_max_output_tokens,
        "temperature": settings.ai_temperature,
        "top_p": settings.ai_top_p,
        "gpu_layer_count": settings.ai_gpu_layers,
        "maximum_gpu_memory_target_mb": settings.ai_gpu_memory_target_mb,
        "request_timeout": settings.ai_timeout_seconds,
        "maximum_concurrent_ai_tasks": settings.ai_max_concurrent_tasks,
        "maximum_analysis_iterations": settings.ai_max_iterations,
        "maximum_tool_calls": settings.ai_max_tool_calls,
        "maximum_retrieved_chunks": settings.ai_max_retrieved_chunks,
        "maximum_repository_tokens_per_task": settings.ai_max_repository_tokens,
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
