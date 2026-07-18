import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from nope_api import __version__
from nope_api.ai import check_ai_health, explain_finding, finding_action
from nope_api.auth import AuthRateLimitError, create_or_login, delete_session, get_user_for_token, init_auth_db
from nope_api.config import get_settings
from nope_api.db import migration_status, run_migrations
from nope_api.drift import BaselineSnapshot, baseline_snapshot, compare_scans
from nope_api.findings import finding_detail, parse_finding_query, query_findings, raw_artifact
from nope_api.github import BlockedGitHubAdapter
from nope_api.ingestion import extract_zip
from nope_api.lifecycle import LifecycleTransitionRequest
from nope_api.models import AuthorizationScope, FindingStatus, GitHubSettings, Project, ProjectSettings, Scan, ScanMode, ScanRequest, SystemSettings
from nope_api.queue import clear_scan_cancel, enqueue_scan_job, queue_status, request_scan_cancel, scan_events
from nope_api.reports import ReportContext, render_report
from nope_api.sandbox import sandbox_health
from nope_api.scanners import scanner_capabilities, scanner_health
from nope_api.security import validate_url_scope
from nope_api.settings_contracts import (
    GITHUB_SETTINGS_KEY,
    SYSTEM_SETTINGS_KEY,
    default_system_settings,
    github_status_from_payload,
    prepare_github_payload,
    prepare_project_settings_payload,
    project_settings_key,
    sanitize_project_settings_payload,
)
from nope_api.storage import store

settings = get_settings()
github_adapter = BlockedGitHubAdapter(store)

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
    except AuthRateLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
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


def _system_settings_for(owner_user_id: str | None) -> SystemSettings:
    saved = store.get_application_setting(owner_user_id, SYSTEM_SETTINGS_KEY)
    if saved:
        return SystemSettings(**saved["value"])
    return default_system_settings(settings)


def _normalized_source(value: str | None) -> str | None:
    cleaned = (value or "").strip().lower()
    if not cleaned or cleaned == "uploaded zip":
        return None
    return cleaned


def _scan_source(scan: Scan) -> str | None:
    return _normalized_source(scan.repository_name) or _normalized_source(scan.target_url)


def _snapshot_source(snapshot: BaselineSnapshot) -> str | None:
    return _normalized_source(snapshot.repository_snapshot.get("repository_name")) or _normalized_source(snapshot.target)


def _scans_comparable(current: Scan, reference: Scan) -> bool:
    if current.project_id or reference.project_id:
        return bool(current.project_id and current.project_id == reference.project_id)
    current_source = _scan_source(current)
    reference_source = _scan_source(reference)
    return bool(current_source and current_source == reference_source)


def _baseline_comparable(current: Scan, baseline: dict, snapshot: BaselineSnapshot) -> bool:
    baseline_project = baseline.get("project_id")
    if current.project_id or baseline_project:
        return bool(current.project_id and current.project_id == baseline_project)
    current_source = _scan_source(current)
    reference_source = _snapshot_source(snapshot)
    return bool(current_source and current_source == reference_source)


SCAFFOLD_MINIMUM_MATCH_PERCENT = 30
SCAFFOLD_IGNORED_PARTS = {
    ".git",
    ".hg",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
}


def _repository_scaffold(root: Path, limit: int = 800) -> list[str]:
    entries: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        parts = relative.parts
        if not parts or any(part in SCAFFOLD_IGNORED_PARTS for part in parts):
            continue
        normalized = "/".join(parts)
        if path.is_dir():
            entries.add(f"dir:{normalized}")
        elif path.is_file():
            entries.add(f"file:{normalized}")
            if path.parent != root:
                entries.add(f"dir:{path.parent.relative_to(root).as_posix()}")
        if len(entries) >= limit:
            break
    return sorted(entries)


def _scaffold_similarity(current: list[str], reference: list[str]) -> int:
    current_set = set(current)
    reference_set = set(reference)
    if not current_set or not reference_set:
        return 100
    return round((len(current_set & reference_set) / len(current_set | reference_set)) * 100)


def _latest_project_scaffold(project_id: str, owner_user_id: str | None, exclude_scan_id: str | None = None) -> list[str]:
    for scan in store.list_scans(owner_user_id):
        if scan.project_id != project_id or scan.id == exclude_scan_id:
            continue
        if scan.repository_scaffold:
            return scan.repository_scaffold
    return []


def _validate_project_upload(scan: Scan, owner_user_id: str | None, root: Path, force_scaffold: bool) -> None:
    scan.repository_scaffold = _repository_scaffold(root)
    scan.repository_scaffold_similarity = None
    if not scan.project_id:
        return
    if not store.user_owns_project(scan.project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project folder not found.")
    previous_scaffold = _latest_project_scaffold(scan.project_id, owner_user_id, scan.id)
    if not previous_scaffold:
        scan.repository_scaffold_similarity = 100
        return
    similarity = _scaffold_similarity(scan.repository_scaffold, previous_scaffold)
    scan.repository_scaffold_similarity = similarity
    if similarity < SCAFFOLD_MINIMUM_MATCH_PERCENT and not force_scaffold:
        raise HTTPException(
            status_code=409,
            detail=(
                f"This ZIP only matches this folder by {similarity}%. "
                "It looks like a different project. Enable the scaffold override to upload anyway."
            ),
        )


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
        snapshot = BaselineSnapshot(**baseline["data"])
        if not _baseline_comparable(current, baseline, snapshot):
            raise HTTPException(status_code=409, detail="Baseline belongs to a different repository or target.")
        return snapshot
    if against_scan_id:
        reference = _load_scan(against_scan_id, authorization)
        if not _scans_comparable(current, reference):
            raise HTTPException(status_code=409, detail="Scans belong to different repositories or targets.")
        return reference
    candidates = [
        scan
        for scan in store.list_scans(owner_user_id)
        if scan.id != current.id and _scans_comparable(current, scan)
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


@app.get("/api/settings/system", response_model=SystemSettings)
def get_system_settings(authorization: str | None = Header(default=None)) -> SystemSettings:
    owner_user_id = _require_owner_user_id(authorization)
    return _system_settings_for(owner_user_id)


@app.put("/api/settings/system", response_model=SystemSettings)
def put_system_settings(payload: SystemSettings, authorization: str | None = Header(default=None)) -> SystemSettings:
    owner_user_id = _require_owner_user_id(authorization)
    saved = store.save_application_setting(owner_user_id, SYSTEM_SETTINGS_KEY, payload.model_dump(mode="json"))
    store.record_audit_log("settings.system.updated", owner_user_id, data={"key": SYSTEM_SETTINGS_KEY})
    return SystemSettings(**saved["value"])


@app.get("/api/projects/{project_id}/settings", response_model=ProjectSettings, response_model_exclude_none=True)
def get_project_settings(project_id: str, authorization: str | None = Header(default=None)) -> ProjectSettings:
    owner_user_id = _require_owner_user_id(authorization)
    if not store.user_owns_project(project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project not found.")
    saved = store.get_application_setting(owner_user_id, project_settings_key(project_id))
    if not saved:
        return ProjectSettings(project_id=project_id)
    return ProjectSettings(**sanitize_project_settings_payload(saved["value"]))


@app.put("/api/projects/{project_id}/settings", response_model=ProjectSettings, response_model_exclude_none=True)
def put_project_settings(project_id: str, payload: ProjectSettings, authorization: str | None = Header(default=None)) -> ProjectSettings:
    owner_user_id = _require_owner_user_id(authorization)
    if payload.project_id != project_id:
        raise HTTPException(status_code=400, detail="Project setting payload must match the route project_id.")
    if not store.user_owns_project(project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project not found.")
    key = project_settings_key(project_id)
    existing = store.get_application_setting(owner_user_id, key)
    value = prepare_project_settings_payload(settings, payload, existing["value"] if existing else None)
    saved = store.save_application_setting(owner_user_id, key, value)
    store.record_audit_log("settings.project.updated", owner_user_id, project_id=project_id, data={"key": key})
    return ProjectSettings(**sanitize_project_settings_payload(saved["value"]))


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str, authorization: str | None = Header(default=None)) -> dict:
    owner_user_id = _require_owner_user_id(authorization)
    if not store.user_owns_project(project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project not found.")
    for scan in store.list_scans(owner_user_id):
        if scan.project_id == project_id:
            await request_scan_cancel(settings, scan.id)
    store.record_audit_log("project.deleted", owner_user_id, project_id=project_id, data={"project_id": project_id})
    deleted = store.delete_project(project_id, owner_user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"ok": True, "project_id": project_id}


@app.get("/api/github/status")
def get_github_status(authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    if not owner_user_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return github_adapter.status(owner_user_id)


@app.put("/api/github/settings")
def put_github_settings(payload: GitHubSettings, authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    if not owner_user_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    existing = store.get_github_contract(owner_user_id)
    value = prepare_github_payload(settings, payload, existing["data"] if existing else None)
    status = github_status_from_payload(value).status
    store.save_github_contract(owner_user_id, value, status)
    store.save_application_setting(owner_user_id, GITHUB_SETTINGS_KEY, value)
    store.record_audit_log("github.contract.updated", owner_user_id, data={"status": status})
    return github_status_from_payload(value)


@app.get("/api/github/repositories")
def list_github_repositories(authorization: str | None = Header(default=None)):
    owner_user_id = _require_owner_user_id(authorization)
    if not owner_user_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return github_adapter.list_repositories(owner_user_id)


@app.get("/api/github/callback")
def github_callback(authorization: str | None = Header(default=None)):
    _require_owner_user_id(authorization)
    raise HTTPException(status_code=409, detail=github_adapter.callback_blocked_detail())


@app.get("/api/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str, authorization: str | None = Header(default=None)) -> Scan:
    return _load_scan(scan_id, authorization)


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str, authorization: str | None = Header(default=None)) -> dict:
    owner_user_id = _require_owner_user_id(authorization)
    scan = _load_scan(scan_id, authorization)
    await request_scan_cancel(settings, scan_id)
    deleted = store.delete_scan(scan_id, owner_user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found.")
    store.record_audit_log("scan.deleted", owner_user_id, project_id=scan.project_id, data={"scan_id": scan.id})
    return {"ok": True, "scan_id": scan_id}


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
    owner_user_id = _require_owner_user_id(authorization)
    detail = finding_detail(_load_scan(scan_id, authorization), finding_id, store.list_finding_lifecycle_events(scan_id, finding_id, owner_user_id))
    if not detail:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return detail


@app.patch("/api/scans/{scan_id}/findings/{finding_id}/lifecycle", response_model=Scan)
def transition_finding_lifecycle(scan_id: str, finding_id: str, payload: LifecycleTransitionRequest, authorization: str | None = Header(default=None)) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    try:
        scan = store.transition_finding(scan_id, finding_id, payload, owner_user_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not scan:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return scan


@app.post("/api/scans/{scan_id}/findings/{finding_id}/suppress", response_model=Scan)
def suppress_finding(scan_id: str, finding_id: str, payload: dict, authorization: str | None = Header(default=None)) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    expiry = payload.get("expiry")
    if not str(payload.get("reason") or "").strip():
        raise HTTPException(status_code=400, detail="Suppression reason is required.")
    request = LifecycleTransitionRequest(
        status=FindingStatus.suppressed,
        reason=str(payload.get("reason") or ""),
        actor=str(payload.get("actor") or payload.get("user") or owner_user_id or "local-user"),
        expiry=datetime.fromisoformat(expiry) if expiry else None,
        scope=str(payload.get("scope") or "finding"),
        expected_version=payload.get("expected_version"),
    )
    try:
        scan = store.transition_finding(scan_id, finding_id, request, owner_user_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not scan:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return scan


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
async def get_scan_events(
    scan_id: str,
    authorization: str | None = Header(default=None),
    after_sequence: int | None = None,
    limit: int = 100,
) -> dict:
    owner_user_id = _require_owner_user_id(authorization)
    return await scan_events(_load_scan(scan_id, authorization), owner_user_id, after_sequence=after_sequence, limit=limit)


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
            store.record_scan_event(
                scan.id,
                "report_started",
                owner_user_id=owner_user_id,
                new_state="running",
                progress=100 if scan.status in {"completed", "partial", "failed", "cancelled"} else None,
                message="PDF report generation started.",
                metadata={"format": fmt, "source": "download"},
                idempotency_key="report:pdf:download:started",
            )
            context = ReportContext(
                drift_events=store.list_drift_events(scan_id, owner_user_id),
                baselines=store.list_security_baselines(owner_user_id, scan.project_id),
            )
            media_type, body = render_report(scan, fmt, context)
            store.save_report(scan, fmt, media_type, body, owner_user_id=owner_user_id)
            store.record_scan_event(
                scan.id,
                "report_completed",
                owner_user_id=owner_user_id,
                new_state="completed",
                progress=100 if scan.status in {"completed", "partial", "failed", "cancelled"} else None,
                message="PDF report generation completed.",
                metadata={"format": fmt, "source": "download"},
                idempotency_key="report:pdf:download:completed",
            )
        else:
            stored_report = store.get_report(scan_id, fmt, owner_user_id)
            if stored_report:
                media_type, body = stored_report
            else:
                store.record_scan_event(
                    scan.id,
                    "report_started",
                    owner_user_id=owner_user_id,
                    new_state="running",
                    progress=100 if scan.status in {"completed", "partial", "failed", "cancelled"} else None,
                    message=f"{fmt.upper()} report generation started.",
                    metadata={"format": fmt, "source": "download"},
                    idempotency_key=f"report:{fmt}:download:started",
                )
                media_type, body = render_report(scan, fmt)
                store.save_report(scan, fmt, media_type, body, owner_user_id=owner_user_id)
                store.record_scan_event(
                    scan.id,
                    "report_completed",
                    owner_user_id=owner_user_id,
                    new_state="completed",
                    progress=100 if scan.status in {"completed", "partial", "failed", "cancelled"} else None,
                    message=f"{fmt.upper()} report generation completed.",
                    metadata={"format": fmt, "source": "download"},
                    idempotency_key=f"report:{fmt}:download:completed",
                )
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
    if request.project_id and not store.user_owns_project(request.project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project folder not found.")
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
    store.record_scan_event(scan.id, "scan_created", owner_user_id=owner_user_id, new_state="queued", progress=0, message="URL scan created.", idempotency_key="scan_created")
    store.record_scan_event(scan.id, "scan_queued", owner_user_id=owner_user_id, previous_state="created", new_state="queued", progress=0, message="URL scan queued for worker.", idempotency_key="scan_queued")
    await enqueue_scan_job(settings, {"scan_id": scan.id, "owner_user_id": owner_user_id, "mode": scan.mode.value})
    return scan


@app.post("/api/scans/repository", response_model=Scan)
async def start_repository_scan(
    file: UploadFile = File(...),
    project_id: str | None = Form(default=None),
    repository_name: str | None = Form(default="Uploaded ZIP"),
    branch: str | None = Form(default=None),
    commit_sha: str | None = Form(default=None),
    force_scaffold: bool = Form(False),
    authorization: str | None = Header(default=None),
) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    if project_id and not store.user_owns_project(project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project folder not found.")
    scan = Scan(
        project_id=project_id,
        mode=ScanMode.repository,
        repository_name=repository_name,
        status="preparing",
        branch=branch,
        commit_sha=commit_sha,
    )
    store.save_scan(scan, owner_user_id)
    store.record_scan_event(scan.id, "scan_created", owner_user_id=owner_user_id, new_state="preparing", progress=0, message="Repository scan created.", idempotency_key="scan_created")
    store.record_scan_event(scan.id, "scan_preparing", owner_user_id=owner_user_id, previous_state="created", new_state="preparing", progress=3, message="Repository ZIP is being prepared.", idempotency_key="scan_preparing")
    try:
        root = await extract_zip(file, scan.id, settings)
        _validate_project_upload(scan, owner_user_id, root, force_scaffold)
    except HTTPException:
        store.delete_scan(scan.id, owner_user_id)
        shutil.rmtree(settings.temp_root / scan.id, ignore_errors=True)
        raise
    scan.repository_workspace_path = str(root)
    scan.status = "queued"
    scan.stages.append({"name": "Queued for worker", "status": "queued", "message": "Repository extracted and ready."})
    store.save_scan(scan, owner_user_id)
    store.record_scan_event(scan.id, "stage_queued", owner_user_id=owner_user_id, stage_id="stage:queued", new_state="queued", progress=0, message="Repository extracted and ready.", idempotency_key="stage:queued")
    store.record_scan_event(scan.id, "scan_queued", owner_user_id=owner_user_id, previous_state="preparing", new_state="queued", progress=0, message="Repository scan queued for worker.", idempotency_key="scan_queued")
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
    force_scaffold: bool = Form(False),
    authorization: str | None = Header(default=None),
) -> Scan:
    owner_user_id = _require_owner_user_id(authorization)
    if project_id and not store.user_owns_project(project_id, owner_user_id):
        raise HTTPException(status_code=404, detail="Project folder not found.")
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
    store.record_scan_event(scan.id, "scan_created", owner_user_id=owner_user_id, new_state="preparing", progress=0, message="Full scan created.", idempotency_key="scan_created")
    store.record_scan_event(scan.id, "scan_preparing", owner_user_id=owner_user_id, previous_state="created", new_state="preparing", progress=3, message="Repository ZIP and URL scope are being prepared.", idempotency_key="scan_preparing")
    try:
        root = await extract_zip(file, scan.id, settings)
        _validate_project_upload(scan, owner_user_id, root, force_scaffold)
    except HTTPException:
        store.delete_scan(scan.id, owner_user_id)
        shutil.rmtree(settings.temp_root / scan.id, ignore_errors=True)
        raise
    scan.repository_workspace_path = str(root)
    scan.status = "queued"
    scan.stages.append({"name": "Queued for worker", "status": "queued", "message": "Repository extracted and URL scope confirmed."})
    store.save_scan(scan, owner_user_id)
    store.record_scan_event(scan.id, "stage_queued", owner_user_id=owner_user_id, stage_id="stage:queued", new_state="queued", progress=0, message="Repository extracted and URL scope confirmed.", idempotency_key="stage:queued")
    store.record_scan_event(scan.id, "scan_queued", owner_user_id=owner_user_id, previous_state="preparing", new_state="queued", progress=0, message="Full scan queued for worker.", idempotency_key="scan_queued")
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
    store.record_scan_event(
        scan.id,
        "cancellation_requested",
        owner_user_id=owner_user_id,
        previous_state=scan.status,
        new_state="cancelling",
        progress=None,
        message="Cancellation requested by user.",
        idempotency_key=f"cancellation_requested:{scan.status}",
    )
    if scan.status in {"queued", "preparing"}:
        scan.status = "cancelled"
        scan.completed_at = datetime.now(timezone.utc)
        store.record_scan_event(
            scan.id,
            "cancellation_acknowledged",
            owner_user_id=owner_user_id,
            previous_state="cancelling",
            new_state="cancelled",
            progress=100,
            message="Cancellation acknowledged before worker execution.",
            idempotency_key="cancellation_acknowledged",
        )
        store.record_scan_event(
            scan.id,
            "scan_cancelled",
            owner_user_id=owner_user_id,
            previous_state="queued",
            new_state="cancelled",
            progress=100,
            message="Scan cancelled before worker execution.",
            idempotency_key="scan_cancelled",
        )
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
    store.record_scan_event(
        scan.id,
        "retry_scheduled",
        owner_user_id=owner_user_id,
        previous_state="failed",
        new_state="queued",
        progress=0,
        message="Manual retry queued.",
        idempotency_key=f"manual_retry:{datetime.now(timezone.utc).isoformat()}",
    )
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
    owner_user_id = _require_owner_user_id(authorization)
    persisted = _system_settings_for(owner_user_id)
    return {
        "provider": settings.ai_provider if persisted.runtime != "disabled" else "none",
        "model_name": settings.ai_model_name,
        "model_file_path": settings.qwen_model_path,
        "runtime_endpoint": persisted.qwen_endpoint,
        "context_length": persisted.context,
        "maximum_output_tokens": persisted.output_limit,
        "temperature": settings.ai_temperature,
        "top_p": settings.ai_top_p,
        "gpu_layer_count": persisted.gpu_layers,
        "maximum_gpu_memory_target_mb": settings.effective_qwen_gpu_memory_target_mb,
        "batch_size": settings.qwen_batch_size,
        "threads": settings.qwen_threads,
        "parallel": settings.qwen_parallel,
        "request_timeout": persisted.timeout,
        "maximum_concurrent_ai_tasks": persisted.concurrency,
        "maximum_analysis_iterations": settings.ai_max_iterations,
        "maximum_tool_calls": settings.ai_max_tool_calls,
        "maximum_retrieved_chunks": settings.ai_max_retrieved_chunks,
        "maximum_repository_tokens_per_task": settings.ai_max_repository_tokens,
        "rag": {
            "maximum_files": settings.ai_rag_max_files,
            "maximum_repository_files_considered": settings.ai_rag_max_repository_files,
            "maximum_file_bytes_considered": settings.ai_rag_max_file_bytes,
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
    owner_user_id = _require_owner_user_id(authorization)
    from nope_api.models import Finding

    parsed = Finding(**finding)
    scan, root = _scan_context_for_finding(parsed.scan_id, owner_user_id)
    return await explain_finding(settings, parsed, root=root, scan=scan)


@app.post("/api/findings/{action}")
async def finding_action_endpoint(action: str, finding: dict, authorization: str | None = Header(default=None)) -> dict:
    owner_user_id = _require_owner_user_id(authorization)
    if action not in {"explain", "challenge", "fix", "test"}:
        raise HTTPException(status_code=404, detail="Unsupported finding AI action.")
    from nope_api.models import Finding

    parsed = Finding(**finding)
    scan, root = _scan_context_for_finding(parsed.scan_id, owner_user_id)
    return await finding_action(settings, parsed, action, root=root, scan=scan)  # type: ignore[arg-type]


def _scan_context_for_finding(scan_id: str | None, owner_user_id: str) -> tuple[Scan | None, Path | None]:
    if not scan_id:
        return None, None
    scan = store.get_scan(scan_id, owner_user_id)
    if not scan:
        return None, None
    root = Path(scan.repository_workspace_path) if scan.repository_workspace_path else None
    if root and not root.exists():
        root = None
    return scan, root
