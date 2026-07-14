from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from nope_api import __version__
from nope_api.ai import check_ai_health, explain_finding
from nope_api.auth import create_or_login, delete_session, get_user_for_token, init_auth_db
from nope_api.config import get_settings
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
    try:
        init_auth_db(settings)
    except Exception:
        # Core scanning must still start if Postgres is temporarily unavailable.
        pass


@app.get("/health")
async def health() -> dict:
    production_warnings = settings.validate_production_secrets()
    ai_health = await check_ai_health(settings)
    return {
        "status": "ok" if not production_warnings else "degraded",
        "version": __version__,
        "environment": settings.environment,
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
def list_projects() -> list[Project]:
    return store.list_projects()


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


@app.post("/api/projects", response_model=Project)
def create_project(project: Project) -> Project:
    return store.create_project(project.name, project.repository, project.target_url)


@app.get("/api/scans", response_model=list[Scan])
def list_scans() -> list[Scan]:
    return store.list_scans()


@app.get("/api/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str) -> Scan:
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str):
    return get_scan(scan_id).findings


@app.get("/api/scans/{scan_id}/coverage")
def get_coverage(scan_id: str):
    return get_scan(scan_id).coverage


@app.get("/api/scans/{scan_id}/attack-map")
def get_attack_map(scan_id: str):
    scan = get_scan(scan_id)
    return {"attack_surface": scan.attack_surface, "code_graph": scan.code_graph}


@app.get("/api/scans/{scan_id}/report.{fmt}")
def get_report(scan_id: str, fmt: str):
    scan = get_scan(scan_id)
    try:
        media_type, body = render_report(scan, fmt)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(content=body, media_type=media_type)


@app.post("/api/scans/url", response_model=Scan)
async def start_url_scan(request: ScanRequest) -> Scan:
    if request.mode != ScanMode.url:
        raise HTTPException(status_code=400, detail="Use mode=url for this endpoint.")
    if not request.target_url:
        raise HTTPException(status_code=400, detail="target_url is required.")
    authorization = validate_url_scope(str(request.target_url), request.authorization, settings)
    if authorization.confirmed_at is None:
        authorization.confirmed_at = datetime.now(timezone.utc)
    scan = Scan(
        project_id=request.project_id,
        mode=ScanMode.url,
        target_url=str(request.target_url),
    )
    store.save_scan(scan)
    scan = await run_url_only_scan(scan, settings)
    return store.save_scan(scan)


@app.post("/api/scans/repository", response_model=Scan)
async def start_repository_scan(
    file: UploadFile = File(...),
    project_id: str | None = Form(default=None),
    repository_name: str | None = Form(default="Uploaded ZIP"),
    branch: str | None = Form(default=None),
    commit_sha: str | None = Form(default=None),
) -> Scan:
    scan = Scan(
        project_id=project_id,
        mode=ScanMode.repository,
        repository_name=repository_name,
        branch=branch,
        commit_sha=commit_sha,
    )
    store.save_scan(scan)
    root = await extract_zip(file, scan.id, settings)
    scan = await run_repository_scan(scan, root, settings)
    return store.save_scan(scan)


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
) -> Scan:
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
    store.save_scan(scan)
    root = await extract_zip(file, scan.id, settings)
    scan = await run_full_scan(scan, root, settings)
    return store.save_scan(scan)


@app.get("/api/settings/model")
def model_settings() -> dict:
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
async def test_model() -> dict:
    health_result = await check_ai_health(settings)
    status = "Complete" if health_result["status"] == "ok" else "Failed"
    if health_result["status"] == "disabled":
        status = "Not tested"
    return {"status": status, **health_result}


@app.post("/api/findings/explain")
async def explain_finding_endpoint(finding: dict) -> dict:
    from nope_api.models import Finding

    parsed = Finding(**finding)
    return await explain_finding(settings, parsed)
