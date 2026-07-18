import json
from pathlib import Path

import pytest

from nope_api.config import Settings
from nope_api.models import CoverageRecord, CoverageStatus, Scan, ScanMode, ScannerRun
from nope_api.reports import render_report
from nope_api.sandbox import (
    SandboxCommandResult,
    ZAP_JSON_BEGIN,
    ZAP_JSON_END,
    ZAP_VERSION_BEGIN,
    ZAP_VERSION_END,
    run_sandbox_assessment,
)
from nope_api.url_scanner import scan_url


def write_manifest(root: Path, payload: dict) -> None:
    (root / ".nope").mkdir()
    (root / ".nope" / "sandbox.json").write_text(json.dumps(payload), encoding="utf-8")


def zap_stdout(alerts: list[dict] | None = None) -> str:
    report = {"site": [{"@name": "http://nope-sandbox-app:8080", "alerts": alerts or []}]}
    return (
        "zap started\n"
        f"{ZAP_VERSION_BEGIN}\n2.16.1\n{ZAP_VERSION_END}\n"
        f"{ZAP_JSON_BEGIN}\n{json.dumps(report)}\n{ZAP_JSON_END}\n"
    )


class Stage4Executor:
    def __init__(self, *, readiness_status: str = "passed", zap_status: str = "passed", zap_alerts: list[dict] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.readiness_status = readiness_status
        self.zap_status = zap_status
        self.zap_alerts = zap_alerts or []

    def run(self, command: list[str], timeout_seconds: int) -> SandboxCommandResult:
        self.commands.append(command)
        rendered = " ".join(command)
        if "urllib.request.urlopen" in rendered:
            status = self.readiness_status
            return SandboxCommandResult(status=status, name=command[0], command=command, exit_code=0 if status == "passed" else 1, message="ready" if status == "passed" else "not ready")
        if "zap-baseline.py" in rendered:
            status = self.zap_status
            return SandboxCommandResult(status=status, name=command[0], command=command, exit_code=0 if status == "passed" else 3, stdout=zap_stdout(self.zap_alerts), message="zap")
        return SandboxCommandResult(status="passed", name=command[0], command=command, exit_code=0, message="ok")


def _manifest(command: str = "node server.js", kind: str = "node") -> dict:
    return {
        "version": 1,
        "workflows": [{"name": "build", "kind": kind, "command": "npm run build" if kind == "node" else "python -m compileall ."}],
        "startup": {"kind": kind, "command": command, "port": 8080, "readiness_path": "/"},
        "zap": {"enabled": True, "max_minutes": 1, "auth_state": "unauthenticated", "target_path": "/"},
    }


def test_stage4_zap_baseline_parses_alerts_and_stores_artifact(tmp_path):
    write_manifest(tmp_path, _manifest())
    (tmp_path / "server.js").write_text("require('http').createServer((req,res)=>res.end('ok')).listen(8080)\n", encoding="utf-8")
    alert = {
        "pluginid": "10020",
        "alert": "Missing Anti-clickjacking Header",
        "riskdesc": "Medium (High)",
        "confidence": "High",
        "desc": "The response did not include a clickjacking defense.",
        "solution": "Set X-Frame-Options or frame-ancestors.",
        "instances": [{"uri": "http://nope-sandbox-app:8080/", "method": "GET", "evidence": "X-Frame-Options"}],
    }

    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), Stage4Executor(zap_alerts=[alert]))

    assert any(run.scanner == "OWASP ZAP" and run.status == "passed" and run.version == "2.16.1" for run in runs)
    assert any(finding.scanner == "OWASP ZAP" and finding.original_rule_id == "zap:10020" for finding in findings)
    assert coverage[0].status == CoverageStatus.partial
    assert "unauthenticated" in coverage[0].notes
    zap_artifact = next(item["artifact"] for item in artifacts if item["name"] == "OWASP ZAP baseline")
    assert zap_artifact["raw_report"]["site"][0]["alerts"][0]["pluginid"] == "10020"
    assert zap_artifact["configuration"]["network"] == "runner-created internal Docker network"
    assert zap_artifact["cleanup_performed"] is True


def test_stage4_zap_uses_private_network_and_readiness_probe(tmp_path):
    write_manifest(tmp_path, _manifest(command="python app.py", kind="python"))

    executor = Stage4Executor()
    run_sandbox_assessment(tmp_path, Settings(), executor)
    commands = " \n".join(" ".join(command) for command in executor.commands)
    assert "network create --internal" in commands
    assert "urllib.request.urlopen" in commands
    assert "zap-baseline.py -t http://nope-sandbox-app-" in commands
    assert "http://example.com" not in commands


@pytest.mark.parametrize(
    "fixture",
    ["stage4-node-dynamic", "stage4-python-dynamic"],
)
def test_stage4_supported_dynamic_fixtures_execute_build_startup_and_zap(fixture):
    root = Path(__file__).parent / "fixtures" / fixture
    executor = Stage4Executor()

    runs, findings, coverage, artifacts = run_sandbox_assessment(root, Settings(), executor)

    commands = " \n".join(" ".join(command) for command in executor.commands)
    assert runs[0].status == "passed"
    assert any(run.scanner == "OWASP ZAP" for run in runs)
    assert findings == []
    assert coverage[0].domain == "Dynamic testing"
    assert coverage[0].status == CoverageStatus.partial
    assert "npm run build" in commands or "python -m compileall ." in commands
    assert "node server.js" in commands or "python app.py" in commands
    assert artifacts[-1]["artifact"]["configuration"]["mode"] == "baseline"


def test_stage4_readiness_failure_reports_failed_startup_coverage(tmp_path):
    write_manifest(tmp_path, _manifest(command="python app.py", kind="python"))

    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), Stage4Executor(readiness_status="failed"))

    assert runs[0].status == "failed"
    assert findings[0].title.startswith("Sandbox workflow failed")
    assert coverage[0].status == CoverageStatus.failed
    assert "readiness failed" in coverage[0].notes.lower()
    assert artifacts[-1]["artifact"]["type"] == "zap_readiness"


def test_stage4_build_failure_skips_zap_instead_of_claiming_dynamic_success(tmp_path):
    write_manifest(tmp_path, _manifest(command="python app.py", kind="python"))

    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), Stage4Executor(readiness_status="passed", zap_status="passed"))
    assert any(run.scanner == "OWASP ZAP" and run.status == "passed" for run in runs)

    class BuildFailExecutor(Stage4Executor):
        def run(self, command: list[str], timeout_seconds: int) -> SandboxCommandResult:
            rendered = " ".join(command)
            if "python -m compileall ." in rendered:
                self.commands.append(command)
                return SandboxCommandResult(status="failed", name=command[0], command=command, exit_code=1, message="build failed")
            return super().run(command, timeout_seconds)

    executor = BuildFailExecutor()
    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), executor)
    commands = " \n".join(" ".join(command) for command in executor.commands)

    assert any(run.scanner == "OWASP ZAP" and run.status == "skipped" for run in runs)
    assert findings[0].title.startswith("Sandbox workflow failed")
    assert coverage[0].status == CoverageStatus.failed
    assert "zap-baseline.py" not in commands
    assert artifacts[-1]["artifact"]["type"] == "zap_skipped"


def test_stage4_unsupported_dynamic_startup_is_reported_honestly(tmp_path):
    write_manifest(tmp_path, _manifest(command="python manage.py runserver 0.0.0.0:8080", kind="python"))

    runs, findings, coverage, artifacts = run_sandbox_assessment(tmp_path, Settings(), Stage4Executor())

    assert runs[0].status == "failed"
    assert findings[0].fingerprint.startswith("sandbox:")
    assert coverage[0].status == CoverageStatus.failed
    assert "not allowed" in artifacts[-1]["message"]


def test_stage4_reports_show_dynamic_coverage_and_zap_artifact():
    scan = Scan(id="scan_stage4_report", mode=ScanMode.repository)
    scan.scanner_runs = [
        ScannerRun(scanner="OWASP ZAP", version="2.16.1", status="passed", message="ZAP baseline completed.", findings_count=1, raw_artifact_id="art_zap")
    ]
    scan.coverage = [
        CoverageRecord(
            domain="Dynamic testing",
            status=CoverageStatus.partial,
            scanners=["NOPE sandbox", "OWASP ZAP"],
            notes="ZAP baseline completed unauthenticated.",
        )
    ]

    media_type, body = render_report(scan, "md")

    assert media_type == "text/markdown"
    assert "## Dynamic Testing" in body
    assert "Dynamic testing" in body
    assert "art_zap" in body


@pytest.mark.asyncio
async def test_stage4_url_scan_blocks_unauthorized_external_targets():
    _findings, runs, coverage = await scan_url("http://127.0.0.1:8080", Settings())

    assert runs[0].status == "failed"
    assert coverage[0].status == CoverageStatus.failed
    assert "private" in runs[0].message.lower() or "not allowed" in runs[0].message.lower()
