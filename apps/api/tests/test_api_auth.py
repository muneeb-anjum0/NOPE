from uuid import uuid4

from fastapi.testclient import TestClient

from nope_api.main import app


def test_scan_api_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/api/scans")
    assert response.status_code == 401


def test_authenticated_api_scopes_projects_to_user():
    suffix = uuid4().hex[:8]
    first_email = f"phase1-first-{suffix}@example.com"
    second_email = f"phase1-second-{suffix}@example.com"

    with TestClient(app) as client:
        first_login = client.post(
            "/api/auth/login",
            json={"email": first_email, "password": "correct horse battery staple"},
        )
        second_login = client.post(
            "/api/auth/login",
            json={"email": second_email, "password": "correct horse battery staple"},
        )
        first_token = first_login.json()["token"]
        second_token = second_login.json()["token"]

        created = client.post(
            "/api/projects",
            headers={"authorization": f"Bearer {first_token}"},
            json={"name": f"Scoped {suffix}", "repository": "repo.zip"},
        )
        assert created.status_code == 200

        first_projects = client.get(
            "/api/projects",
            headers={"authorization": f"Bearer {first_token}"},
        )
        second_projects = client.get(
            "/api/projects",
            headers={"authorization": f"Bearer {second_token}"},
        )

    assert any(project["name"] == f"Scoped {suffix}" for project in first_projects.json())
    assert all(project["name"] != f"Scoped {suffix}" for project in second_projects.json())
