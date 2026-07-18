from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import time
from typing import Any, Protocol

import httpx
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
    kind: str = "python"
    port: int = 8080
    readiness_path: str = "/"
    timeout_seconds: int | None = None


class SandboxZap(BaseModel):
    enabled: bool = False
    image: str | None = None
    max_minutes: int = 1
    auth_state: str = "unauthenticated"
    target_path: str = "/"


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
    artifact: dict[str, Any] | None = None


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


ZAP_JSON_BEGIN = "NOPE_ZAP_JSON_BEGIN"
ZAP_JSON_END = "NOPE_ZAP_JSON_END"
ZAP_VERSION_BEGIN = "NOPE_ZAP_VERSION_BEGIN"
ZAP_VERSION_END = "NOPE_ZAP_VERSION_END"


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
        "network_default": "disabled; ZAP uses only a runner-created internal network",
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
    if settings.sandbox_runner_url and executor is None:
        return _run_remote_sandbox_assessment(root, settings)
    return _run_local_sandbox_assessment(root, settings, executor)


def _run_remote_sandbox_assessment(
    root: Path,
    settings: Settings,
) -> tuple[list[ScannerRun], list[Finding], list[CoverageRecord], list[dict[str, Any]]]:
    try:
        response = httpx.post(
            f"{settings.sandbox_runner_url.rstrip('/')}/runner/sandbox",
            headers={"authorization": f"Bearer {settings.sandbox_runner_token}"},
            json={"workspace_path": str(root.resolve())},
            timeout=settings.sandbox_timeout_seconds + settings.sandbox_zap_timeout_seconds + 15,
        )
        response.raise_for_status()
        payload = response.json()
        return (
            [ScannerRun(**item) for item in payload.get("scanner_runs", [])],
            [Finding(**item) for item in payload.get("findings", [])],
            [CoverageRecord(**item) for item in payload.get("coverage", [])],
            list(payload.get("artifacts", [])),
        )
    except Exception as exc:
        started = now_utc()
        message = f"Sandbox runner unavailable or rejected the job: {_bounded_redacted(str(exc), 512)}"
        return (
            [ScannerRun(scanner="NOPE sandbox", version="runner", status="failed", coverage_categories=["Dynamic testing"], started_at=started, completed_at=now_utc(), message=message)],
            [],
            [CoverageRecord(domain="Dynamic testing", status=CoverageStatus.failed, scanners=["NOPE sandbox"], notes=message)],
            [{"name": "Sandbox runner", "status": "failed", "message": message, "isolation": sandbox_limits(settings)}],
        )


def _run_local_sandbox_assessment(
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
    workflow_failed = any(result.status in {"failed", "timed_out", "unsupported"} for result in workflow_results)
    zap_result = None
    if manifest.zap.enabled and workflow_failed:
        zap_result = SandboxCommandResult(
            status="skipped",
            name="OWASP ZAP baseline",
            command=[],
            message="ZAP skipped because an earlier sandbox build or workflow failed.",
            artifact={
                "type": "zap_skipped",
                "reason": "build_or_workflow_failed",
                "auth_state": manifest.zap.auth_state,
                "configuration": {"mode": "baseline", "requested": True},
            },
        )
    elif manifest.zap.enabled:
        zap_result = runner.run_zap(manifest.startup, manifest.zap)
    results = workflow_results + ([zap_result] if zap_result else [])
    failed = [result for result in results if result.status in {"failed", "timed_out", "unsupported"}]
    passed = [result for result in results if result.status == "passed"]
    status = "passed" if passed and not failed else "failed" if failed else "skipped"
    coverage_status = CoverageStatus.verified if status == "passed" else CoverageStatus.failed if failed else CoverageStatus.not_tested
    zap_findings = _findings_from_zap_artifact(root, zap_result.artifact) if zap_result else []
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
    runs = [run]
    if zap_result:
        zap_status = "passed" if zap_result.status == "passed" else "skipped" if zap_result.status == "skipped" else "failed"
        runs.append(
            ScannerRun(
                scanner="OWASP ZAP",
                version=str((zap_result.artifact or {}).get("zap_version") or (manifest.zap.image or settings.sandbox_zap_image)),
                status=zap_status,
                coverage_categories=["Dynamic testing", "URL scanning", "Security headers"],
                started_at=started,
                completed_at=now_utc(),
                message=zap_result.message,
                findings_count=len(zap_findings),
                command=zap_result.command,
                exit_code=zap_result.exit_code,
                raw_stdout=json.dumps(zap_result.artifact or {}, sort_keys=True),
                raw_stderr=zap_result.stderr,
            )
        )
    findings = [_finding_for_failure(root, result) for result in failed] + zap_findings
    coverage_notes = _dynamic_coverage_notes(manifest, zap_result, message)
    if zap_result and zap_result.status != "passed":
        coverage_status = CoverageStatus.failed
    elif zap_result and manifest.zap.auth_state != "authenticated":
        coverage_status = CoverageStatus.partial
    coverage = [CoverageRecord(domain="Dynamic testing", status=coverage_status, scanners=[run.scanner for run in runs], notes=coverage_notes)]
    artifacts = [result_payload(result, settings) for result in results]
    return runs, findings, coverage, artifacts


class DockerSandbox:
    def __init__(self, settings: Settings, root: Path, executor: SandboxExecutor) -> None:
        self.settings = settings
        self.root = root.resolve()
        self.executor = executor

    def run_workflow(self, workflow: SandboxWorkflow) -> SandboxCommandResult:
        image = workflow.image or self._default_image(workflow.kind)
        if not self._image_allowed(image):
            return SandboxCommandResult(status="unsupported", name=workflow.name, command=[], message=f"Image is not allowed for sandbox workflow: {image}")
        if not self._command_allowed(workflow.command):
            return SandboxCommandResult(status="unsupported", name=workflow.name, command=[], message=f"Command is not allowed for sandbox workflow: {workflow.command}")
        timeout = min(workflow.timeout_seconds or self.settings.sandbox_timeout_seconds, self.settings.sandbox_timeout_seconds)
        name = f"nope-sandbox-{new_id('run')}"
        command = self._docker_run_command(
            name=name,
            image=image,
            inner_command=f"cp -R {self._repository_source_path()}/. /workspace && cd /workspace && {workflow.command}",
            network="none",
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
        app_image = startup.image or self._default_image(startup.kind)
        zap_image = zap.image or self.settings.sandbox_zap_image
        if not self._image_allowed(app_image) or not self._image_allowed(zap_image):
            return SandboxCommandResult(status="unsupported", name="OWASP ZAP baseline", command=[], message="Startup or ZAP image is not allowed.")
        if not self._command_allowed(startup.command):
            return SandboxCommandResult(status="unsupported", name="OWASP ZAP baseline", command=[], message="Startup command is not allowed.")
        network = f"nope-sandbox-net-{new_id('net')}"
        app_name = f"nope-sandbox-app-{new_id('app')}"
        target_url = self._internal_target_url(app_name, startup.port, zap.target_path)
        readiness_url = self._internal_target_url(app_name, startup.port, startup.readiness_path)
        readiness_name = f"nope-sandbox-ready-{new_id('ready')}"
        zap_name = f"nope-sandbox-zap-{new_id('zap')}"
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
                name=readiness_name,
                image=self.settings.sandbox_python_image,
                inner_command=self._readiness_probe_command(readiness_url),
                network=network,
                detach=False,
                mount_repository=False,
                read_only=True,
                user="65532:65532",
            ),
            self._docker_run_command(
                name=zap_name,
                image=zap_image,
                inner_command=self._zap_baseline_command(target_url, zap.max_minutes),
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
                    result.message = f"Dynamic startup failed: {result.message or result.status}"
                    return result
            readiness = self.executor.run(commands[2], startup.timeout_seconds or self.settings.sandbox_startup_timeout_seconds)
            if readiness.status != "passed":
                readiness.name = "OWASP ZAP baseline"
                readiness.cleanup_performed = self._cleanup(cleanup_commands)
                readiness.message = f"Dynamic readiness failed for {readiness_url}: {readiness.message or readiness.status}"
                readiness.artifact = {
                    "type": "zap_readiness",
                    "target_url": target_url,
                    "readiness_url": readiness_url,
                    "status": readiness.status,
                    "auth_state": zap.auth_state,
                    "cleanup_performed": readiness.cleanup_performed,
                }
                return readiness
            zap_result = self.executor.run(commands[3], self.settings.sandbox_zap_timeout_seconds)
            zap_result.name = "OWASP ZAP baseline"
            zap_result.cleanup_performed = self._cleanup(cleanup_commands)
            zap_result.artifact = _zap_artifact_from_output(
                stdout=zap_result.stdout,
                stderr=zap_result.stderr,
                target_url=target_url,
                readiness_url=readiness_url,
                auth_state=zap.auth_state,
                zap_image=zap_image,
                max_minutes=zap.max_minutes,
                cleanup_performed=zap_result.cleanup_performed,
                isolation=sandbox_limits(self.settings),
            )
            if zap_result.status == "timed_out":
                zap_result.message = f"ZAP baseline timed out after {self.settings.sandbox_zap_timeout_seconds}s."
            elif zap_result.status != "passed":
                zap_result.message = f"ZAP baseline failed or crashed: {zap_result.message or zap_result.status}"
            else:
                alerts = len((zap_result.artifact or {}).get("alerts", []))
                zap_result.message = f"ZAP baseline completed against internal target; {alerts} alert(s) parsed; auth={zap.auth_state}."
            zap_result.stdout = _bounded_redacted(zap_result.stdout, self.settings.sandbox_log_bytes)
            zap_result.stderr = _bounded_redacted(zap_result.stderr, self.settings.sandbox_log_bytes)
            return zap_result
        finally:
            self._cleanup(cleanup_commands)

    def _internal_target_url(self, container_name: str, port: int, path: str) -> str:
        safe_path = path if path.startswith("/") else f"/{path}"
        return f"http://{container_name}:{port}{safe_path}"

    def _readiness_probe_command(self, readiness_url: str) -> str:
        return (
            "python - <<'PY'\n"
            "import sys, time, urllib.request\n"
            f"url = {readiness_url!r}\n"
            "deadline = time.time() + 15\n"
            "last = None\n"
            "while time.time() < deadline:\n"
            "    try:\n"
            "        with urllib.request.urlopen(url, timeout=2) as response:\n"
            "            if response.status < 500:\n"
            "                print(f'ready {response.status}')\n"
            "                sys.exit(0)\n"
            "    except Exception as exc:\n"
            "        last = exc\n"
            "    time.sleep(0.5)\n"
            "print(f'not ready: {last}', file=sys.stderr)\n"
            "sys.exit(1)\n"
            "PY"
        )

    def _zap_baseline_command(self, target_url: str, max_minutes: int) -> str:
        return (
            "set +e; "
            "zap.sh -version > /tmp/nope_zap_version.txt 2>/dev/null; "
            f"/zap/zap-baseline.py -t {target_url} -m {max_minutes} -I -J /tmp/nope_zap.json > /tmp/nope_zap_stdout.txt 2> /tmp/nope_zap_stderr.txt; "
            "code=$?; "
            "cat /tmp/nope_zap_stdout.txt; "
            f"echo {ZAP_VERSION_BEGIN}; cat /tmp/nope_zap_version.txt 2>/dev/null || true; echo {ZAP_VERSION_END}; "
            f"echo {ZAP_JSON_BEGIN}; cat /tmp/nope_zap.json 2>/dev/null || true; echo {ZAP_JSON_END}; "
            "cat /tmp/nope_zap_stderr.txt >&2; "
            "if [ \"$code\" -gt 2 ]; then exit \"$code\"; fi; exit 0"
        )

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

    def _command_allowed(self, command: str) -> bool:
        allowed = {item.strip() for item in self.settings.sandbox_allow_commands.split(",") if item.strip()}
        return command.strip() in allowed

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


def _dynamic_coverage_notes(manifest: SandboxManifest, zap_result: SandboxCommandResult | None, fallback: str) -> str:
    if not manifest.zap.enabled:
        return "Sandbox workflows ran, but ZAP dynamic testing was not enabled in the manifest."
    if not zap_result:
        return "ZAP dynamic testing was requested but did not produce a scanner result."
    if zap_result.status == "skipped":
        return zap_result.message or "ZAP dynamic testing was skipped."
    if zap_result.status != "passed":
        return zap_result.message or "ZAP dynamic testing failed."
    auth_state = manifest.zap.auth_state or "unauthenticated"
    alert_count = len((zap_result.artifact or {}).get("alerts", []))
    if auth_state == "authenticated":
        return f"ZAP baseline completed with configured authentication state; {alert_count} alert(s) parsed."
    return f"ZAP baseline completed unauthenticated on an internal target; {alert_count} alert(s) parsed. Authenticated endpoints may be partial or skipped."


def _extract_marker(text: str, begin: str, end: str) -> str:
    if begin not in text or end not in text:
        return ""
    return text.split(begin, 1)[1].split(end, 1)[0].strip()


def _zap_artifact_from_output(
    *,
    stdout: str,
    stderr: str,
    target_url: str,
    readiness_url: str,
    auth_state: str,
    zap_image: str,
    max_minutes: int,
    cleanup_performed: bool,
    isolation: dict[str, Any],
) -> dict[str, Any]:
    raw_json_text = _extract_marker(stdout, ZAP_JSON_BEGIN, ZAP_JSON_END)
    version = _extract_marker(stdout, ZAP_VERSION_BEGIN, ZAP_VERSION_END) or zap_image
    raw_report: dict[str, Any] = {}
    parse_error = ""
    if raw_json_text:
        try:
            raw_report = json.loads(raw_json_text)
        except json.JSONDecodeError as exc:
            parse_error = str(exc)
    alerts = _parse_zap_alerts(raw_report)
    return {
        "type": "zap_baseline",
        "scanner": "OWASP ZAP",
        "zap_version": version.strip(),
        "zap_image": zap_image,
        "configuration": {
            "mode": "baseline",
            "target_url": target_url,
            "readiness_url": readiness_url,
            "max_minutes": max_minutes,
            "auth_state": auth_state or "unauthenticated",
            "network": "runner-created internal Docker network",
            "redirect_policy": "ZAP target is internal-only; external URL redirects are handled by NOPE URL scanner scope checks.",
        },
        "raw_report": raw_report,
        "raw_report_parse_error": parse_error,
        "alerts": alerts,
        "stdout": _bounded_redacted(stdout, 64 * 1024),
        "stderr": _bounded_redacted(stderr, 64 * 1024),
        "cleanup_performed": cleanup_performed,
        "isolation": isolation,
    }


def _parse_zap_alerts(raw_report: dict[str, Any]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for site in raw_report.get("site", []) if isinstance(raw_report, dict) else []:
        site_name = site.get("@name") or site.get("name") or ""
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances") or [{}]
            for instance in instances:
                uri = instance.get("uri") or site_name
                parsed.append(
                    {
                        "plugin_id": str(alert.get("pluginid") or alert.get("pluginId") or alert.get("id") or "unknown"),
                        "alert": str(alert.get("alert") or alert.get("name") or "ZAP alert"),
                        "risk": str(alert.get("riskdesc") or alert.get("risk") or alert.get("riskcode") or "Informational"),
                        "confidence": str(alert.get("confidence") or alert.get("confidenceDesc") or "medium"),
                        "description": str(alert.get("desc") or alert.get("description") or ""),
                        "solution": str(alert.get("solution") or ""),
                        "reference": str(alert.get("reference") or ""),
                        "uri": str(uri or ""),
                        "method": str(instance.get("method") or ""),
                        "param": str(instance.get("param") or ""),
                        "evidence": str(instance.get("evidence") or ""),
                    }
                )
    return parsed


def _zap_severity(risk: str) -> Severity:
    normalized = risk.lower()
    if "critical" in normalized:
        return Severity.critical
    if "high" in normalized:
        return Severity.high
    if "medium" in normalized:
        return Severity.medium
    if "low" in normalized:
        return Severity.low
    return Severity.info


def _zap_confidence(confidence: str) -> Confidence:
    normalized = confidence.lower()
    if "high" in normalized:
        return Confidence.high
    if "low" in normalized:
        return Confidence.low
    return Confidence.medium


def _zap_fingerprint(alert: dict[str, Any]) -> str:
    payload = "|".join(
        [
            "zap",
            str(alert.get("plugin_id") or ""),
            str(alert.get("uri") or ""),
            str(alert.get("method") or ""),
            str(alert.get("param") or ""),
            str(alert.get("alert") or ""),
        ]
    )
    return sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _findings_from_zap_artifact(root: Path, artifact: dict[str, Any] | None) -> list[Finding]:
    if not artifact:
        return []
    findings: list[Finding] = []
    for alert in artifact.get("alerts", []):
        title = str(alert.get("alert") or "ZAP dynamic alert")
        uri = str(alert.get("uri") or artifact.get("configuration", {}).get("target_url") or "")
        method = str(alert.get("method") or "GET")
        risk = str(alert.get("risk") or "")
        description = str(alert.get("description") or title)
        solution = str(alert.get("solution") or "Review the dynamic finding, validate exploitability, and apply the remediation recommended by OWASP ZAP.")
        findings.append(
            Finding(
                fingerprint=_zap_fingerprint(alert),
                scanner="OWASP ZAP",
                original_rule_id=f"zap:{alert.get('plugin_id')}",
                title=title,
                description=description,
                severity=_zap_severity(risk),
                original_severity=risk,
                confidence=_zap_confidence(str(alert.get("confidence") or "")),
                original_confidence=str(alert.get("confidence") or ""),
                category="Dynamic testing",
                affected_file=str(root.name),
                affected_route=uri,
                endpoint=uri,
                scanner_sources=["OWASP ZAP", "NOPE sandbox"],
                evidence=[
                    Evidence(
                        source="OWASP ZAP",
                        route=uri,
                        endpoint=uri,
                        message=f"{method} {uri}; param={alert.get('param') or 'n/a'}; evidence={alert.get('evidence') or 'n/a'}",
                    )
                ],
                remediation=solution,
                code_flow_fingerprint=f"dynamic:{method}:{uri}",
            )
        )
    return findings


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
        "artifact": result.artifact,
    }


def _cleanup_target_missing(result: SandboxCommandResult) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return "no such" in output or "not found" in output
