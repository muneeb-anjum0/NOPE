from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from nope_api.config import Settings, get_settings
from nope_api.sandbox import _run_local_sandbox_assessment, sandbox_health


class SandboxRunnerRequest(BaseModel):
    workspace_path: str


settings = get_settings()
app = FastAPI(title="NOPE Runner", description="Internal sandbox runner boundary.", version="0.1.0")


def _require_runner_token(authorization: str | None) -> None:
    token = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not token or token != settings.sandbox_runner_token:
        raise HTTPException(status_code=401, detail="Runner request is not authorized.")


def _safe_workspace(path: str, settings: Settings) -> Path:
    root = Path(settings.temp_root).resolve()
    requested = Path(path).resolve()
    try:
        requested.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Runner workspace is outside the controlled workspace root.") from exc
    if not requested.exists() or not requested.is_dir():
        raise HTTPException(status_code=404, detail="Runner workspace does not exist.")
    return requested


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "sandbox": sandbox_health(settings)}


@app.post("/runner/sandbox")
def run_sandbox(payload: SandboxRunnerRequest, authorization: str | None = Header(default=None)) -> dict:
    _require_runner_token(authorization)
    workspace = _safe_workspace(payload.workspace_path, settings)
    local_settings = settings.model_copy(update={"sandbox_runner_url": ""})
    runs, findings, coverage, artifacts = _run_local_sandbox_assessment(workspace, local_settings)
    return {
        "scanner_runs": [run.model_dump(mode="json") for run in runs],
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "coverage": [record.model_dump(mode="json") for record in coverage],
        "artifacts": artifacts,
    }
