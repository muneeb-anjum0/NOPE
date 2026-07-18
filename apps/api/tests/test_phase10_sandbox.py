import json
from pathlib import Path

import pytest

from nope_api.config import Settings
from nope_api.models import CoverageStatus, Scan, ScanMode
from nope_api.sandbox import (
    DockerSandbox,
    SandboxCommandResult,
    SandboxStartup,
    SandboxWorkflow,
    SandboxZap,
    load_manifest,
    run_sandbox_assessment,
    sandbox_health,
)
from nope_api.scan_engine import run_repository_scan


class FakeExecutor:
    def __init__(self, statuses: list[str] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.statuses = statuses or []

    def run(self, command: list[str], timeout_seconds: int) -> SandboxCommandResult:
        self.commands.append(command)
        status = self.statuses.pop(0) if self.statuses else "passed"
        return SandboxCommandResult(
            status=status,
            name=command[0],
            command=command,
            exit_code=0 if status == "passed" else 1,
            stdout="ok",
            stderr="",
            message="ok" if status == "passed" else "failed",
        )


def write_manifest(root: Path, payload: dict) -> None:
    (root / ".nope").mkdir()
    (root / ".nope" / "sandbox.json").write_text(json.dumps(payload), encoding="utf-8")


def test_manifest_contract_loads_workflows_and_zap(tmp_path):
    write_manifest(
        tmp_path,
        {
            "version": 1,
            "workflows": [{"name": "python compile", "kind": "python", "command": "python -m compileall ."}],
            "startup": {"kind": "python", "command": "python -m http.server 8080 --bind 0.0.0.0", "port": 8080},
            "zap": {"enabled": True, "max_minutes": 1},
        },
    )

    manifest, error = load_manifest(tmp_path)

    assert error is None
    assert manifest is not None
    assert manifest.workflows[0].name == "python compile"
    assert manifest.startup is not None
    assert manifest.startup.kind == "python"
    assert manifest.zap.enabled is True


def test_docker_workflow_command_enforces_sandbox_isolation(tmp_path):
    executor = FakeExecutor()
    sandbox = DockerSandbox(Settings(sandbox_timeout_seconds=30), tmp_path, executor)

    result = sandbox.run_workflow(SandboxWorkflow(name="static", kind="python", command="python -m compileall ."))

    command = executor.commands[0]
    rendered = " ".join(command)
    assert result.status == "passed"
    assert "--network none" in rendered
    assert "--read-only" in command
    assert "--cap-drop ALL" in rendered
    assert "--security-opt no-new-privileges:true" in rendered
    assert "--pids-limit 128" in rendered
    assert "--memory 512m" in rendered
    assert "target=/workspace-src,readonly" in rendered
    assert "/var/run/docker.sock" not in rendered
    assert rendered.count("--mount") == 1
    assert "NOPE_MINIO" not in rendered


def test_worker_workspace_volume_mounts_shared_workspace_read_only(tmp_path):
    root = tmp_path / "scan-workspace"
    root.mkdir()
    executor = FakeExecutor()
    sandbox = DockerSandbox(Settings(temp_root=str(tmp_path), sandbox_workspace_volume="nope_nope-workspaces"), root, executor)

    sandbox.run_workflow(SandboxWorkflow(name="worker", kind="python", command="python -m compileall ."))

    rendered = " ".join(executor.commands[0])
    assert "type=volume,source=nope_nope-workspaces,target=/workspace-volume,readonly" in rendered
    assert "cp -R /workspace-volume/scan-workspace/. /workspace" in rendered
    assert "target=/workspace-src" not in rendered


def test_sandbox_absent_manifest_marks_dynamic_testing_not_applicable(tmp_path):
    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), FakeExecutor())

    assert runs[0].status == "skipped"
    assert findings == []
    assert artifacts[0]["status"] == "skipped"
    assert coverage[0].domain == "Dynamic testing"
    assert coverage[0].status == CoverageStatus.not_applicable


def test_failed_workflow_creates_finding_and_failed_coverage(tmp_path):
    write_manifest(tmp_path, {"workflows": [{"name": "tests", "kind": "python", "command": "python -m pytest"}]})
    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), FakeExecutor(["failed"]))

    assert runs[0].status == "failed"
    assert findings[0].scanner == "NOPE sandbox"
    assert findings[0].category == "Dynamic testing"
    assert coverage[0].status == CoverageStatus.failed
    assert artifacts[0]["isolation"]["docker_socket_mounted"] is False


def test_timed_out_workflow_forces_container_cleanup(tmp_path):
    executor = FakeExecutor(["timed_out", "passed"])
    sandbox = DockerSandbox(
        Settings(sandbox_timeout_seconds=2, sandbox_allow_commands='python -c "while True: pass"'),
        tmp_path,
        executor,
    )

    result = sandbox.run_workflow(SandboxWorkflow(name="loop", kind="python", command="python -c \"while True: pass\""))

    assert result.status == "timed_out"
    assert result.cleanup_performed is True
    assert any(command[:3] == ["docker", "rm", "-f"] for command in executor.commands)


def test_zap_workflow_uses_private_network_and_cleans_up(tmp_path):
    executor = FakeExecutor(["passed", "passed", "passed", "passed", "passed", "passed"])
    sandbox = DockerSandbox(Settings(), tmp_path, executor)

    result = sandbox.run_zap(
        SandboxStartup(command="python -m http.server 8080 --bind 0.0.0.0", port=8080),
        SandboxZap(enabled=True, max_minutes=1),
    )

    rendered = [" ".join(command) for command in executor.commands]
    assert result.status == "passed"
    assert any("network create --internal" in command for command in rendered)
    assert any("urllib.request.urlopen" in command for command in rendered)
    assert any("zap-baseline.py -t http://nope-sandbox-app-" in command for command in rendered)
    assert any(" rm -f nope-sandbox-app-" in command for command in rendered)
    assert any("network rm nope-sandbox-net-" in command for command in rendered)


def test_sandbox_health_reports_limits_without_claiming_runtime_success(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda command: "C:/Program Files/Docker/docker.exe" if command == "docker" else None)
    health = sandbox_health(Settings())

    assert health["enabled"] is True
    assert health["docker_available"] is True
    assert health["limits"]["docker_socket_mounted"] is False
    assert health["limits"]["nope_secrets_forwarded"] is False


@pytest.mark.asyncio
async def test_repository_scan_includes_sandbox_stage(monkeypatch, tmp_path):
    write_manifest(tmp_path, {"workflows": [{"name": "compile", "kind": "python", "command": "python -m compileall ."}]})
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    async def fake_ai_review(settings, findings, root=None, scan=None):
        return scan.ai_review

    monkeypatch.setattr("nope_api.scan_engine.scanner_plugins", lambda: [])
    monkeypatch.setattr("nope_api.scan_engine.run_ai_review", fake_ai_review)
    monkeypatch.setattr(
        "nope_api.scan_engine.run_sandbox_assessment",
        lambda root, settings: (
            [],
            [],
            [CoverageRecord(domain="Dynamic testing", status=CoverageStatus.verified, scanners=["NOPE sandbox"], notes="ok")],
            [{"name": "compile", "status": "passed"}],
        ),
    )

    from nope_api.models import CoverageRecord

    scan = await run_repository_scan(Scan(id="scan_phase10_unit", mode=ScanMode.repository), tmp_path, Settings())

    assert any(stage["name"] == "Running sandbox workflows" for stage in scan.stages)
    assert any(record.domain == "Dynamic testing" and record.status == CoverageStatus.verified for record in scan.coverage)
