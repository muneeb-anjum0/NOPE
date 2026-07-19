from __future__ import annotations

from io import BytesIO
from uuid import uuid4
from zipfile import ZipFile

import httpx
import pytest
from fastapi.testclient import TestClient

from nope_api.db import connect
from nope_api.github import GitHubApiClient, SecureGitHubAdapter
from nope_api.main import app, settings
from nope_api.storage import store


def login(client: TestClient, suffix: str, label: str = "user") -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": f"stage9-{label}-{suffix}@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()["token"]


def auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def fake_zip(files: dict[str, str]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


class FakeGitHub:
    def __init__(self, archive: bytes | None = None, status: int = 200) -> None:
        self.archive = archive or fake_zip({"repo-main/app.py": "print('hello')\n"})
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers.get("authorization") == "Bearer ghp_stage9_secret"
        if self.status != 200:
            return httpx.Response(self.status, json={"message": "revoked"})
        path = request.url.path
        if path == "/user/repos":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 1001,
                        "full_name": "acme/private-app",
                        "default_branch": "main",
                        "private": True,
                        "html_url": "https://github.example/acme/private-app",
                        "permissions": {"pull": True, "push": False, "admin": False},
                        "size": 42,
                        "archived": False,
                        "pushed_at": "2026-07-19T00:00:00Z",
                    }
                ],
            )
        if path == "/repos/acme/private-app":
            return httpx.Response(
                200,
                json={
                    "id": 1001,
                    "full_name": "acme/private-app",
                    "default_branch": "main",
                    "private": True,
                    "html_url": "https://github.example/acme/private-app",
                    "permissions": {"pull": True},
                    "size": 42,
                },
            )
        if path == "/repos/acme/private-app/commits/main":
            return httpx.Response(200, json={"sha": "abc123def456"})
        if path == "/repos/acme/private-app/zipball/main":
            return httpx.Response(200, content=self.archive, headers={"content-type": "application/zip"})
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture
def fake_github_adapter(monkeypatch):
    fake = FakeGitHub()
    adapter = SecureGitHubAdapter(store, settings, GitHubApiClient(settings, transport=httpx.MockTransport(fake)))
    import nope_api.main as main_module

    monkeypatch.setattr(main_module, "github_adapter", adapter)

    async def noop_enqueue(*args, **kwargs):
        return None

    monkeypatch.setattr(main_module, "enqueue_scan_job", noop_enqueue)
    return fake


def test_stage9_token_storage_state_validation_repository_listing_and_disconnect(fake_github_adapter):
    suffix = f"contracts-{uuid4().hex[:8]}"
    with TestClient(app) as client:
        token = login(client, suffix)
        saved = client.put(
            "/api/github/settings",
            headers=auth(token),
            json={
                "client_id": "Iv1.stage9",
                "access_token": "ghp_stage9_secret",
                "callback_url": "http://localhost:8000/api/github/callback",
            },
        )
        assert saved.status_code == 200
        assert saved.json()["status"] == "blocked_external_credentials_not_verified"
        assert saved.json()["credential_state"]["access_token"] is True
        assert "ghp_stage9_secret" not in saved.text

        state = client.post("/api/github/connect", headers=auth(token))
        assert state.status_code == 200
        assert len(state.json()["state"]) > 20

        rejected = client.get("/api/github/callback?state=wrong", headers=auth(token))
        assert rejected.status_code == 400

        accepted = client.get(f"/api/github/callback?state={state.json()['state']}&code=abc", headers=auth(token))
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "blocked_external_credentials_not_verified"

        repos = client.get("/api/github/repositories", headers=auth(token))
        assert repos.status_code == 200
        assert repos.json()["status"] == "connected"
        assert repos.json()["repositories"][0]["full_name"] == "acme/private-app"
        assert repos.json()["repositories"][0]["default_branch"] == "main"

        disconnected = client.delete("/api/github/connection", headers=auth(token))
        assert disconnected.status_code == 200
        assert disconnected.json()["status"] == "blocked_token_revoked"

    owner_id = _user_id_for_email(f"stage9-user-{suffix}@example.com")
    contract = store.get_github_contract(owner_id)
    assert contract is not None
    assert "ghp_stage9_secret" not in str(contract["data"])
    assert "access_token" not in contract["data"]
    assert store.list_github_repository_references(owner_id) == []


def test_stage9_repository_snapshot_scan_and_secret_safe_reports(fake_github_adapter):
    with TestClient(app) as client:
        token = login(client, "scan")
        project = client.post(
            "/api/projects",
            headers=auth(token),
            json={"name": "Stage 9 GitHub", "repository": "acme/private-app", "target_url": None},
        )
        assert project.status_code == 200
        client.put("/api/github/settings", headers=auth(token), json={"access_token": "ghp_stage9_secret"})
        assert client.get("/api/github/repositories", headers=auth(token)).status_code == 200

        scan = client.post(
            "/api/github/scans/repository",
            headers=auth(token),
            json={"project_id": project.json()["id"], "full_name": "acme/private-app", "branch": "main"},
        )
        assert scan.status_code == 200
        body = scan.json()
        assert body["repository_name"] == "acme/private-app"
        assert body["branch"] == "main"
        assert body["commit_sha"] == "abc123def456"
        assert "ghp_stage9_secret" not in str(body)

        report = client.get(f"/api/scans/{body['id']}/report.json", headers=auth(token))
        assert report.status_code == 200
        assert "ghp_stage9_secret" not in report.text

    with connect(settings) as conn:
        snapshot = conn.execute(
            "select branch, commit_sha, upload_name from repository_snapshots where project_id = %s order by created_at desc limit 1",
            (project.json()["id"],),
        ).fetchone()
    assert snapshot is not None
    assert snapshot["branch"] == "main"
    assert snapshot["commit_sha"] == "abc123def456"
    assert snapshot["upload_name"] == "acme/private-app"


def test_stage9_ownership_isolation_and_policy_failures(monkeypatch):
    fake = FakeGitHub(archive=fake_zip({"repo-main/.gitmodules": "[submodule]\n"}))
    adapter = SecureGitHubAdapter(store, settings, GitHubApiClient(settings, transport=httpx.MockTransport(fake)))
    import nope_api.main as main_module

    monkeypatch.setattr(main_module, "github_adapter", adapter)

    async def noop_enqueue(*args, **kwargs):
        return None

    monkeypatch.setattr(main_module, "enqueue_scan_job", noop_enqueue)
    with TestClient(app) as client:
        owner = login(client, "policy", "owner")
        other = login(client, "policy", "other")
        project = client.post("/api/projects", headers=auth(owner), json={"name": "Owned", "repository": None, "target_url": None})
        assert project.status_code == 200
        client.put("/api/github/settings", headers=auth(owner), json={"access_token": "ghp_stage9_secret"})

        blocked_other = client.post(
            "/api/github/scans/repository",
            headers=auth(other),
            json={"project_id": project.json()["id"], "full_name": "acme/private-app"},
        )
        assert blocked_other.status_code == 404

        policy = client.post(
            "/api/github/scans/repository",
            headers=auth(owner),
            json={"project_id": project.json()["id"], "full_name": "acme/private-app"},
        )
        assert policy.status_code == 409
        assert "submodules" in policy.json()["detail"]


def test_stage9_revoked_token_is_not_silently_accepted(monkeypatch):
    fake = FakeGitHub(status=401)
    adapter = SecureGitHubAdapter(store, settings, GitHubApiClient(settings, transport=httpx.MockTransport(fake)))
    import nope_api.main as main_module

    monkeypatch.setattr(main_module, "github_adapter", adapter)
    with TestClient(app) as client:
        token = login(client, "revoked")
        client.put("/api/github/settings", headers=auth(token), json={"access_token": "ghp_stage9_secret"})
        response = client.get("/api/github/repositories", headers=auth(token))
        assert response.status_code == 401
        status = client.get("/api/github/status", headers=auth(token))
        assert status.status_code == 200
        assert status.json()["status"] == "blocked_token_revoked"


def _user_id_for_email(email: str) -> str:
    with connect(settings) as conn:
        row = conn.execute("select id from local_users where email = %s", (email,)).fetchone()
    assert row is not None
    return str(row["id"])
