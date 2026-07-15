from uuid import uuid4

from fastapi.testclient import TestClient

from nope_api.db import connect
from nope_api.main import app, settings
from nope_api.settings_contracts import decrypt_secret, project_settings_key
from nope_api.storage import store


def login(client: TestClient, suffix: str, label: str = "user") -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": f"phase11-{label}-{suffix}@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()["token"]


def auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def test_system_settings_save_validate_and_persist_to_model_route():
    suffix = uuid4().hex[:8]
    with TestClient(app) as client:
        token = login(client, suffix)
        payload = {
            "qwen_endpoint": "http://nope-ai:8080/custom",
            "runtime": "llama.cpp",
            "context": 3072,
            "gpu_layers": 24,
            "timeout": 120,
            "output_limit": 768,
            "concurrency": 1,
            "scanner_enabled": {"Semgrep": True, "Bandit": False},
            "scanner_timeout": 90,
            "default_scan_mode": "full",
            "retention_days": 45,
            "report_defaults": ["json", "pdf"],
            "artifact_limit_mb": 256,
            "sandbox_limits": {"memory": "512m"},
        }
        saved = client.put("/api/settings/system", headers=auth(token), json=payload)
        assert saved.status_code == 200
        assert saved.json()["qwen_endpoint"] == "http://nope-ai:8080/custom"

        model = client.get("/api/settings/model", headers=auth(token))
        assert model.status_code == 200
        assert model.json()["runtime_endpoint"] == "http://nope-ai:8080/custom"
        assert model.json()["context_length"] == 3072

        invalid = client.put("/api/settings/system", headers=auth(token), json={**payload, "qwen_endpoint": "file:///tmp/model"})
        assert invalid.status_code == 422

    stored = store.get_application_setting(_user_id_for_email(f"phase11-user-{suffix}@example.com"), "system")
    assert stored is not None
    assert stored["value"]["retention_days"] == 45


def test_project_settings_encrypt_test_identity_and_block_cross_user_access():
    suffix = uuid4().hex[:8]
    with TestClient(app) as client:
        owner_token = login(client, suffix, "owner")
        other_token = login(client, suffix, "other")
        project = client.post(
            "/api/projects",
            headers=auth(owner_token),
            json={"name": f"Phase 11 {suffix}", "repository": "repo.zip", "target_url": "https://app.example.com"},
        )
        assert project.status_code == 200
        project_id = project.json()["id"]
        payload = {
            "project_id": project_id,
            "target_url": "https://app.example.com",
            "approved_hosts": ["app.example.com"],
            "excluded_paths": ["/admin"],
            "scanner_overrides": {"Semgrep": True},
            "scan_depth": "deep",
            "test_identities": [{"label": "tester", "username": "alice", "password": "s3cret-phase11"}],
            "baseline_id": None,
            "repository_metadata": {"branch": "main"},
            "authorization_confirmed": True,
            "rag_limits": {"maximum_files": 4},
        }

        saved = client.put(f"/api/projects/{project_id}/settings", headers=auth(owner_token), json=payload)
        assert saved.status_code == 200
        body = saved.json()
        assert body["test_identities_configured"] is True
        assert "password" not in body["test_identities"][0]

        other_get = client.get(f"/api/projects/{project_id}/settings", headers=auth(other_token))
        assert other_get.status_code == 404

    owner_id = _user_id_for_email(f"phase11-owner-{suffix}@example.com")
    stored = store.get_application_setting(owner_id, project_settings_key(project_id))
    raw = stored["value"]
    assert "s3cret-phase11" not in str(raw)
    decrypted = decrypt_secret(settings, raw["test_identities_secret"])
    assert decrypted is not None
    assert "s3cret-phase11" in decrypted


def test_github_contracts_store_encrypted_credentials_and_remain_blocked_without_real_access():
    suffix = uuid4().hex[:8]
    with TestClient(app) as client:
        token = login(client, suffix)
        initial = client.get("/api/github/status", headers=auth(token))
        assert initial.status_code == 200
        assert initial.json()["status"] == "blocked_missing_credentials"

        saved = client.put(
            "/api/github/settings",
            headers=auth(token),
            json={
                "app_id": "12345",
                "client_id": "Iv1.fake",
                "client_secret": "github-client-secret",
                "private_key": "-----BEGIN PRIVATE KEY-----phase11-----END PRIVATE KEY-----",
                "webhook_secret": "webhook-secret",
                "callback_url": "http://localhost:8000/api/github/callback",
                "selected_repository": "owner/private-repo",
                "selected_branch": "main",
            },
        )
        assert saved.status_code == 200
        assert saved.json()["status"] == "blocked_external_credentials_not_verified"
        assert saved.json()["credential_state"]["client_secret"] is True
        assert "github-client-secret" not in saved.text

        repos = client.get("/api/github/repositories", headers=auth(token))
        assert repos.status_code == 200
        assert repos.json()["repositories"] == []
        assert repos.json()["status"].startswith("blocked")

        callback = client.get("/api/github/callback", headers=auth(token))
        assert callback.status_code == 409

    contract = store.get_github_contract(_user_id_for_email(f"phase11-user-{suffix}@example.com"))
    assert contract is not None
    assert "github-client-secret" not in str(contract["data"])
    assert decrypt_secret(settings, contract["data"]["client_secret"]) == "github-client-secret"


def _user_id_for_email(email: str) -> str:
    with connect(settings) as conn:
        row = conn.execute("select id from local_users where email = %s", (email,)).fetchone()
    assert row is not None
    return str(row["id"])
