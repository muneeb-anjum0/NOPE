import time
from pathlib import Path
from threading import Lock

import pytest

from nope_api.config import Settings
from nope_api.models import AIReview, Confidence, Scan, ScanMode, ScannerRun
from nope_api.scan_engine import run_repository_scan


_active_scanners = 0
_max_active_scanners = 0
_scanner_lock = Lock()


class SlowScanner:
    def __init__(self, name: str) -> None:
        self.name = name

    def execute(self, root: Path, settings: Settings):
        global _active_scanners, _max_active_scanners
        with _scanner_lock:
            _active_scanners += 1
            _max_active_scanners = max(_max_active_scanners, _active_scanners)
        try:
            time.sleep(0.25)
        finally:
            with _scanner_lock:
                _active_scanners -= 1
        return (
            ScannerRun(
                scanner=self.name,
                status="passed",
                coverage_categories=["Secrets"],
                findings_count=0,
            ),
            [],
        )


async def fake_ai_review(settings: Settings, findings, root=None, scan=None):
    return AIReview(status="Not tested", provider="none", model="none", confidence=Confidence.low, message="AI disabled for unit test.")


def fake_sandbox(root: Path, settings: Settings):
    return (
        [ScannerRun(scanner="NOPE sandbox", status="skipped", coverage_categories=["Dynamic testing"], message="No sandbox manifest.")],
        [],
        [],
        [],
    )


@pytest.mark.asyncio
async def test_scanner_plugins_run_with_bounded_concurrency(tmp_path, monkeypatch):
    global _active_scanners, _max_active_scanners
    _active_scanners = 0
    _max_active_scanners = 0
    (tmp_path / "package.json").write_text('{"name":"fast-scan"}', encoding="utf-8")
    monkeypatch.setattr("nope_api.scan_engine.scanner_plugins", lambda: [SlowScanner("one"), SlowScanner("two")])
    monkeypatch.setattr("nope_api.scan_engine.run_ai_review", fake_ai_review)
    monkeypatch.setattr("nope_api.scan_engine.run_sandbox_assessment", fake_sandbox)

    started = time.perf_counter()
    scan = await run_repository_scan(
        Scan(id="scan_concurrency", mode=ScanMode.repository),
        tmp_path,
        Settings(scanner_concurrency=2, sandbox_enabled=False),
    )
    elapsed = time.perf_counter() - started

    assert {run.scanner for run in scan.scanner_runs} >= {"one", "two"}
    assert _max_active_scanners == 2
    assert elapsed < 1.0
