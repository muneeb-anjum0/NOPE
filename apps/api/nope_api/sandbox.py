from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time
from typing import Any, Protocol

from pydantic import BaseModel, Field, ValidationError

from nope_api.config import Settings
from nope_api.models import Confidence, CoverageRecord, CoverageStatus, Evidence, Finding, ScannerRun, Severity, new_id, now_utc
from nope_api.scanners import _bounded_redacted


class SandboxWorkflow(BaseModel):
    name: str
    command: str
    image: str | None = None
    kind: str = "custom"
    timeout_seconds: int | None = None
    network: str = "none"


class SandboxStartup(BaseModel):
    command: str
    image: str | None = None
    port: int = 8080
    timeout_seconds: int | None = None


class SandboxZap(BaseModel):
    enabled: bool = False
    image: str | None = None
    max_minutes: int = 1


class SandboxManifest(BaseModel):
    version: int = 1
    workflows: list[SandboxWorkflow] = Field(default_factory=list)
    startup: SandboxStartup | None = None
    zap: SandboxZap = Field(default_factory=SandboxZap)


@dataclass
class SandboxCommandResult:
    status: str
    name: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    message: str = ""
    cleanup_performed: bool = True


class SandboxExecutor(Protocol):
    def run(self, command: list[str], timeout_seconds: int) -> SandboxCommandResult:
        ...


class SubprocessSandboxExecutor:
    def run(self, command: list[str], timeout_seconds: int) -> SandboxCommandResult:
        started = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
            status = "passed" if result.returncode == 0 else "failed"
            return SandboxCommandResult(
                status=status,
                name=command[0],
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=int((time.monotonic() - started) * 1000),
                message="Command completed." if status == "passed" else f"Command exited with {result.returncode}.",
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxCommandResult(
                status="timed_out",
                name=command[0],
                command=command,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                duration_ms=int((time.monotonic() - started) * 1000),
                message="Sandbox command timed out.",
            )
        except FileNotFoundError:
            return SandboxCommandResult(status="unsupported", name=command[0], command=command, message=f"{command[0]} is not available.")


def load_manifest(root: Path) -> tuple[SandboxManifest | None, str | None]:
    manifest_path = root / ".nope" / "sandbox.json"
    if not manifest_path.exists():
        return None, "No .nope/sandbox.json manifest was found."
    try:
        return SandboxManifest(**json.loads(manifest_path.read_text(encoding="utf-8"))), None
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        return None, f"Sandbox manifest is invalid: {exc}"


def sandbox_health(settings: Settings) -> dict[str, Any]:
    docker_path = shutil.which(settings.sandbox_docker_command)
    return {
        "enabled": settings.sandbox_enabled,
        "docker_command": settings.sandbox_docker_command,
        "workspace_volume": settings.sandbox_workspace_volume or None,
        "docker_available": bool(docker_path),
        "docker_path": docker_path,
        "network_default": "disabled" if not settings.sandbox_network_enabled else "enabled by manifest",
        "limits": sandbox_limits(settings),
    }


def sandbox_limits(settings: Settings) -> dict[str, Any]:
    return {
        "memory": settings.sandbox_memory,
        "zap_memory": settings.sandbox_zap_memory,
        "cpus": settings.sandbox_cpus,
        "pids_limit": settings.sandbox_pids_limit,
        "zap_pids_limit": settings.sandbox_zap_pids_limit,
        "timeout_seconds": settings.sandbox_timeout_seconds,
        "startup_timeout_seconds": settings.sandbox_startup_timeout_seconds,
        "zap_timeout_seconds": settings.sandbox_zap_timeout_seconds,
        "tmpfs_size": settings.sandbox_tmpfs_size,
        "log_bytes": settings.sandbox_log_bytes,
        "cap_drop": "ALL",
        "security_opt": "no-new-privileges:true",
        "docker_socket_mounted": False,
        "host_home_mounted": False,
        "nope_secrets_forwarded": False,
    }


def run_sandbox_assessment(
    root: Path,
    settings: Settings,
    executor: SandboxExecutor | None = None,
) -> tuple[list[ScannerRun], list[Finding], list[CoverageRecord], list[dict[str, Any]]]:
    started = now_utc()
    if not settings.sandbox_enabled:
        return (
            [ScannerRun(scanner="NOPE sandbox", version="local", status="skipped", coverage_categories=["Dynamic testing"], started_at=started, completed_at=now_utc(), message="Sandbox execution is disabled.")],
            [],
            [CoverageRecord(domain="Dynamic testing", status=CoverageStatus.not_tested, scanners=["NOPE sandbox"], notes="Sandbox execution is disabled.")],
            [],
        )

    manifest, manifest_error = load_manifest(root)
    if not manifest:
        message = manifest_error or "No sandbox manifest was found."
        return (
            [ScannerRun(scanner="NOPE sandbox", version="local", status="skipped", coverage_categories=["Dynamic testing"], started_at=started, completed_at=now_utc(), message=message)],
            [],
            [CoverageRecord(domain="Dynamic testing", status=CoverageStatus.not_applicable, scanners=["NOPE sandbox"], notes=message)],
            [{"name": "Sandbox manifest", "status": "skipped", "message": message}],
        )

    runner = DockerSandbox(settings, root, executor or SubprocessSandboxExecutor())
    workflow_results = [runner.run_workflow(workflow) for workflow in manifest.workflows]
    zap_result = runner.run_zap(manifest.startup, manifest.zap) if manifest.zap.enabled else None
    results = workflow_results + ([zap_result] if zap_result else [])
    failed = [result for result in results if result.status in {"failed", "timed_out", "unsupported"}]
    passed = [result for result in results if result.status == "passed"]
    status = "passed" if passed and not failed else "failed" if failed else "skipped"
    coverage_status = CoverageStatus.verified if status == "passed" else CoverageStatus.failed if failed else CoverageStatus.not_tested
    message = "; ".join(result.message for result in failed[:3]) or f"{len(passed)} sandbox workflow(s) completed."
    run = ScannerRun(
        scanner="NOPE sandbox",
        version="docker",
        status="passed" if status == "passed" else "failed" if status == "failed" else "skipped",
        coverage_categories=["Dynamic testing"],
        started_at=started,
        completed_at=now_utc(),
        message=message,
        findings_count=len(failed),
        command=[settings.sandbox_docker_command, "run"],
        raw_stdout="\n".join(result.stdout for result in results),
        raw_stderr="\n".join(result.stderr for result in results),
    )
    findings = [_finding_for_failure(root, result) for result in failed]
    coverage = [CoverageRecord(domain="Dynamic testing", status=coverage_status, scanners=["NOPE sandbox"], notes=message)]
    artifacts = [result_payload(result, settings) for result in results]
    return [run], findings, coverage, artifacts


class DockerSandbox:
    def __init__(self, settings: Settings, root: Path, executor: SandboxExecutor) -> None:
        self.settings = settings
        self.root = root.resolve()
        self.executor = executor

    def run_workflow(self, workflow: SandboxWorkflow) -> SandboxCommandResult:
        image = workflow.image or self._default_image(workflow.kind)
        if not self._image_allowed(image):
            return SandboxCommandResult(status="unsupported", name=workflow.name, command=[], message=f"Image is not allowed for sandbox workflow: {image}")
        timeout = min(workflow.timeout_seconds or self.settings.sandbox_timeout_seconds, self.settings.sandbox_timeout_seconds)
        name = f"nope-sandbox-{new_id('run')}"
        command = self._docker_run_command(
            name=name,
            image=image,
            inner_command=f"cp -R {self._repository_source_path()}/. /workspace && cd /workspace && {workflow.command}",
            network="none" if not self.settings.sandbox_network_enabled else workflow.network,
            detach=False,
        )
        result = self.executor.run(command, timeout)
        result.name = workflow.name
        if result.status == "timed_out":
            result.cleanup_performed = self._cleanup([[self.settings.sandbox_docker_command, "rm", "-f", name]])
        result.stdout = _bounded_redacted(result.stdout, self.settings.sandbox_log_bytes)
        result.stderr = _bounded_redacted(result.stderr, self.settings.sandbox_log_bytes)
        return result

    def run_zap(self, startup: SandboxStartup | None, zap: SandboxZap) -> SandboxCommandResult:
        if not startup:
            return SandboxCommandResult(status="unsupported", name="OWASP ZAP baseline", command=[], message="ZAP requires a sandbox startup command.")
        app_image = startup.image or self.settings.sandbox_python_image
        zap_image = zap.image or self.settings.sandbox_zap_image
        if not self._image_allowed(app_image) or not self._image_allowed(zap_image):
            return SandboxCommandResult(status="unsupported", name="OWASP ZAP baseline", command=[], message="Startup or ZAP image is not allowed.")
        network = f"nope-sandbox-net-{new_id('net')}"
        app_name = f"nope-sandbox-app-{new_id('app')}"
        commands: list[list[str]] = [
            [self.settings.sandbox_docker_command, "network", "create", "--internal", network],
            self._docker_run_command(
                name=app_name,
                image=app_image,
                inner_command=f"cp -R {self._repository_source_path()}/. /workspace && cd /workspace && {startup.command}",
                network=network,
                detach=True,
                port=startup.port,
            ),
            self._docker_run_command(
                name=f"nope-sandbox-zap-{new_id('zap')}",
                image=zap_image,
                inner_command=f"sleep 2 && /zap/zap-baseline.py -t http://{app_name}:{startup.port} -m {zap.max_minutes} -I -J /tmp/zap_out.json",
                network=network,
                detach=False,
                mount_repository=False,
                user=None,
                read_only=False,
                memory=self.settings.sandbox_zap_memory,
                pids_limit=self.settings.sandbox_zap_pids_limit,
            ),
            [self.settings.sandbox_docker_command, "rm", "-f", app_name],
            [self.settings.sandbox_docker_command, "network", "rm", network],
        ]
        cleanup_commands = commands[-2:]
        try:
            for command in commands[:2]:
                result = self.executor.run(command, startup.timeout_seconds or self.settings.sandbox_startup_timeout_seconds)
                if result.status != "passed":
                    result.name = "OWASP ZAP baseline"
                    result.cleanup_performed = self._cleanup(cleanup_commands)
                    return result
            zap_result = self.executor.run(commands[2], self.settings.sandbox_zap_timeout_seconds)
            zap_result.name = "OWASP ZAP baseline"
            zap_result.cleanup_performed = self._cleanup(cleanup_commands)
            zap_result.stdout = _bounded_redacted(zap_result.stdout, self.settings.sandbox_log_bytes)
            zap_result.stderr = _bounded_redacted(zap_result.stderr, self.settings.sandbox_log_bytes)
            return zap_result
        finally:
            self._cleanup(cleanup_commands)

    def _cleanup(self, commands: list[list[str]]) -> bool:
        ok = True
        for command in commands:
            success = False
            for _ in range(3):
                result = self.executor.run(command, 10)
                if result.status == "passed" or (result.status == "failed" and _cleanup_target_missing(result)):
                    success = True
                    break
                time.sleep(0.5)
            ok = ok and success
        return ok

    def _default_image(self, kind: str) -> str:
        if kind == "node":
            return self.settings.sandbox_node_image
        if kind == "python":
            return self.settings.sandbox_python_image
        if kind == "static":
            return self.settings.sandbox_static_image
        return self.settings.sandbox_python_image

    def _image_allowed(self, image: str) -> bool:
        prefixes = [item.strip() for item in self.settings.sandbox_allow_images.split(",") if item.strip()]
        return any(image.startswith(prefix) for prefix in prefixes)

    def _docker_run_command(
        self,
        *,
        name: str,
        image: str,
        inner_command: str,
        network: str,
        detach: bool,
        port: int | None = None,
        mount_repository: bool = True,
        user: str | None = "65532:65532",
        read_only: bool = True,
        memory: str | None = None,
        pids_limit: int | None = None,
    ) -> list[str]:
        command = [
            self.settings.sandbox_docker_command,
            "run",
            "--rm" if not detach else "-d",
            "--name",
            name,
            "--network",
            network,
            "--cpus",
            str(self.settings.sandbox_cpus),
            "--memory",
            memory or self.settings.sandbox_memory,
            "--pids-limit",
            str(pids_limit or self.settings.sandbox_pids_limit),
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--tmpfs",
            f"/tmp:rw,nosuid,size={self.settings.sandbox_tmpfs_size},mode=1777",
            "--tmpfs",
            f"/workspace:rw,nosuid,size={self.settings.sandbox_tmpfs_size},mode=1777",
            "--tmpfs",
            " /zap/wrk:rw,nosuid,size=64m,mode=1777".strip(),
            "--env",
            "NOPE_SANDBOX=1",
            "--env",
            "HOME=/tmp",
        ]
        if read_only:
            command.append("--read-only")
        if user:
            command.extend(["--user", user])
        if port:
            command.extend(["--expose", str(port)])
        if mount_repository:
            command.extend(self._repository_mount_args())
        command.extend([image, "sh", "-lc", inner_command])
        return command

    def _repository_source_path(self) -> str:
        if self._workspace_relative_path():
            rel = self._workspace_relative_path()
            return PurePosixPath("/workspace-volume", *rel.parts).as_posix()
        return "/workspace-src"

    def _repository_mount_args(self) -> list[str]:
        if self._workspace_relative_path():
            return ["--mount", f"type=volume,source={self.settings.sandbox_workspace_volume},target=/workspace-volume,readonly"]
        return ["--mount", f"type=bind,source={self.root},target=/workspace-src,readonly"]

    def _workspace_relative_path(self) -> Path | None:
        if not self.settings.sandbox_workspace_volume:
            return None
        try:
            return self.root.relative_to(Path(self.settings.temp_root).resolve())
        except ValueError:
            return None


def _finding_for_failure(root: Path, result: SandboxCommandResult) -> Finding:
    return Finding(
        fingerprint=f"sandbox:{result.name}:{result.status}",
        title=f"Sandbox workflow {result.status}: {result.name}",
        description=result.message or "Sandbox workflow did not complete successfully.",
        severity=Severity.medium if result.status == "failed" else Severity.low,
        confidence=Confidence.high,
        category="Dynamic testing",
        affected_file=str(root.name),
        remediation="Review the sandbox workflow output, fix startup/build/test failures, and rerun the sandbox scan.",
        scanner="NOPE sandbox",
        scanner_sources=["NOPE sandbox"],
        evidence=[Evidence(source="NOPE sandbox", file=str(root.name), message=result.message or result.status)],
    )


def result_payload(result: SandboxCommandResult, settings: Settings) -> dict[str, Any]:
    return {
        "name": result.name,
        "status": result.status,
        "message": result.message,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stdout": _bounded_redacted(result.stdout, settings.sandbox_log_bytes),
        "stderr": _bounded_redacted(result.stderr, settings.sandbox_log_bytes),
        "command": result.command,
        "cleanup_performed": result.cleanup_performed,
        "isolation": sandbox_limits(settings),
    }


def _cleanup_target_missing(result: SandboxCommandResult) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "no such" in output or "not found" in output
