from uuid import uuid4

from fastapi.testclient import TestClient

import nope_api.auth as auth_module
from nope_api.config import Settings
from nope_api.db import connect
from nope_api.main import app


PASSWORD = "correct horse battery staple"


def login(client: TestClient, label: str) -> dict:
    suffix = uuid4().hex[:8]
    response = client.post("/api/auth/login", json={"email": f"stage11-{label}-{suffix}@example.com", "password": PASSWORD})
    assert response.status_code == 200
    return response.json()


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def test_stage11_sessions_are_hashed_at_rest_and_logout_revokes_token():
    with TestClient(app) as client:
        session = login(client, "session")
        token = session["token"]
        with connect(Settings().model_copy(update={"auth_database_url": "postgresql://nope:nope@localhost:5432/nope"})) as conn:
            row = conn.execute("select token from local_sessions where user_id = %s order by expires_at desc limit 1", (session["user"]["id"],)).fetchone()

        assert row is not None
        assert row["token"] != token
        assert len(row["token"]) == 64
        assert client.get("/api/auth/me", headers=bearer(token)).status_code == 200
        assert client.post("/api/auth/logout", headers=bearer(token)).status_code == 200
        assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_stage11_login_rate_limit_uses_shared_redis_when_available(monkeypatch):
    calls: list[tuple[str, str]] = []
    values: dict[str, int] = {}

    class FakeRedis:
        def ping(self):
            return True

        def get(self, key):
            calls.append(("get", key))
            return str(values.get(key, 0))

        def incr(self, key):
            calls.append(("incr", key))
            values[key] = values.get(key, 0) + 1
            return values[key]

        def expire(self, key, seconds):
            calls.append(("expire", key))

        def delete(self, key):
            calls.append(("delete", key))
            values.pop(key, None)

        def close(self):
            calls.append(("close", ""))

    monkeypatch.setattr(auth_module, "_redis_client", lambda settings: FakeRedis())
    email = f"stage11-rate-{uuid4().hex[:8]}@example.com"
    settings = Settings(login_failure_limit=2, login_failure_window_seconds=60)

    auth_module._check_login_rate_limit_shared(settings, email)
    auth_module._record_login_failure_shared(settings, email)
    auth_module._record_login_failure_shared(settings, email)

    assert any(name == "incr" for name, _ in calls)
    try:
        auth_module._check_login_rate_limit_shared(settings, email)
    except auth_module.AuthRateLimitError:
        limited = True
    else:
        limited = False
    assert limited is True


def test_stage11_public_health_is_sanitized_and_detailed_health_requires_auth():
    with TestClient(app) as client:
        public = client.get("/health")
        unauthenticated_details = client.get("/api/health/details")
        session = login(client, "health")
        details = client.get("/api/health/details", headers=bearer(session["token"]))

    assert public.status_code == 200
    assert public.json()["status"] in {"ok", "degraded"}
    assert "database" not in public.json()
    assert "ai" not in public.json()
    assert "scanners" not in public.json()
    assert unauthenticated_details.status_code == 401
    assert details.status_code == 200
    assert "database" in details.json()
    assert "ai" in details.json()


def test_stage11_origin_guard_request_limit_and_security_headers():
    with TestClient(app) as client:
        session = login(client, "boundary")
        blocked_origin = client.post(
            "/api/projects",
            headers={**bearer(session["token"]), "origin": "https://evil.example"},
            json={"name": "Blocked origin"},
        )
        oversized = client.post(
            "/api/projects",
            headers={**bearer(session["token"]), "content-length": str(30 * 1024 * 1024)},
            json={"name": "Huge"},
        )
        ok = client.get("/api/projects", headers=bearer(session["token"]))

    assert blocked_origin.status_code == 403
    assert oversized.status_code == 413
    assert ok.headers["x-content-type-options"] == "nosniff"
    assert ok.headers["x-frame-options"] == "DENY"
    assert ok.headers["referrer-policy"] == "no-referrer"
