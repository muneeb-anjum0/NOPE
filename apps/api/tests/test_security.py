from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

import pytest
from fastapi import HTTPException, UploadFile

from nope_api.config import Settings
from nope_api.ingestion import extract_zip
from nope_api.models import AuthorizationScope
from nope_api.security import redact, validate_url_scope
from nope_api.ai import check_ai_health


def test_url_scan_requires_authorization():
    with pytest.raises(HTTPException):
        validate_url_scope("https://example.com", None, Settings())


def test_url_scope_rejects_unapproved_host():
    with pytest.raises(HTTPException):
        validate_url_scope(
            "https://example.com",
            AuthorizationScope(confirmed=True, approved_hosts=["example.org"]),
            Settings(),
        )


def test_redacts_secret_like_values():
    assert "***REDACTED***" in redact("api_key='sk-test-secret-value'")


@pytest.mark.asyncio
async def test_zip_slip_is_rejected(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("../evil.txt", "nope")
    with archive.open("rb") as handle:
        upload = UploadFile(filename="bad.zip", file=handle)
        settings = Settings(temp_root=tmp_path / "work")
        with pytest.raises(HTTPException):
            await extract_zip(upload, "scan_test", settings)


def test_private_target_blocked_by_default():
    with pytest.raises(HTTPException):
        validate_url_scope(
            "http://127.0.0.1:8000",
            AuthorizationScope(
                confirmed=True,
                confirmed_at=datetime.now(timezone.utc),
                approved_hosts=["127.0.0.1"],
            ),
            Settings(),
        )


@pytest.mark.asyncio
async def test_ai_health_disabled_state():
    result = await check_ai_health(Settings(ai_provider="none"))
    assert result["status"] == "disabled"
