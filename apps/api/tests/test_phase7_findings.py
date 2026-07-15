from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from nope_api.attack_surface import build_attack_surface, build_code_graph
from nope_api.findings import finding_detail, parse_finding_query, query_findings, raw_artifact
from nope_api.main import app
from nope_api.models import BaselineState, Confidence, Evidence, Finding, Scan, ScanMode, ScannerRun, Severity
from nope_api.storage import PostgresStore


def sample_scan(tmp_path: Path) -> Scan:
    suffix = uuid4().hex[:8]
    repo = tmp_path / "repo"
    route = repo / "app/api/invoices/[id]/route.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        """
        export async function GET(req: Request, { params }) {
          return prisma.invoice.findUnique({ where: { id: params.id } });
        }
        """,
        encoding="utf-8",
    )
    surface = build_attack_surface(repo)
    return Scan(
        id=f"scan_phase7_{suffix}",
        mode=ScanMode.repository,
        status="completed",
        repository_workspace_path=str(repo),
        attack_surface=surface,
        code_graph=build_code_graph(repo, surface),
        scanner_runs=[
            ScannerRun(
                scanner="Semgrep",
                status="passed",
                raw_artifact_id="art_semgrep",
                raw_stdout='{"token":"sk-phase7-secret-value-123456"}',
                raw_stderr="",
                findings_count=1,
            )
        ],
        findings=[
            Finding(
                id=f"fnd_idor_{suffix}",
                fingerprint="phase7-idor",
                title="Invoice IDOR",
                description="Invoice lookup lacks owner scope.",
                severity=Severity.high,
                confidence=Confidence.high,
                category="Authorization",
                cwe="CWE-639",
                owasp="A01",
                affected_file="app/api/invoices/[id]/route.ts",
                affected_route="/invoices/:id",
                start_line=3,
                end_line=3,
                symbol="GET",
                remediation="Filter invoice by tenant/user.",
                test_guidance="Add cross-user regression test.",
                scanner_sources=["Semgrep"],
                fix_available=True,
                evidence=[
                    Evidence(source="Semgrep", file="app/api/invoices/[id]/route.ts", line=3, route="/invoices/:id", message="findUnique uses id only.")
                ],
            ),
            Finding(
                id=f"fnd_secret_{suffix}",
                fingerprint="phase7-secret",
                title="Hardcoded secret",
                description="Secret in source.",
                severity=Severity.critical,
                confidence=Confidence.medium,
                category="Secrets",
                affected_file=".env",
                remediation="Rotate the secret.",
                status="reintroduced",
                baseline_state=BaselineState.reintroduced,
                scanner_sources=["Gitleaks"],
                evidence=[Evidence(source="Gitleaks", file=".env", line=1, message="secret found")],
            ),
        ],
    )


def test_finding_filters_sort_pagination_and_flags(tmp_path):
    scan = sample_scan(tmp_path)
    result = query_findings(
        scan,
        parse_finding_query(severity="high", scanner="Semgrep", cwe="CWE-639", fix_available="true", page=1, page_size=1, sort="title"),
    )

    assert result.total == 1
    assert result.items[0].id.startswith("fnd_idor_")
    assert result.filters.fix_available is True
    assert result.pages == 1


def test_reintroduced_and_query_filter(tmp_path):
    scan = sample_scan(tmp_path)
    result = query_findings(scan, parse_finding_query(reintroduced="true", query="secret"))

    assert len(result.items) == 1
    assert result.items[0].id.startswith("fnd_secret_")


def test_finding_detail_returns_code_flow_source_and_history(tmp_path):
    scan = sample_scan(tmp_path)
    detail = finding_detail(scan, scan.findings[0].id)

    assert detail is not None
    assert detail.source is not None
    assert detail.source.available is True
    assert "findUnique" in detail.source.code
    assert detail.code_flow["available"] is True
    assert any(item.event == "first_seen" for item in detail.history)
    assert "evidence" in detail.tabs
    assert "code_flow" in detail.tabs


def test_raw_artifact_is_redacted(tmp_path):
    artifact = raw_artifact(sample_scan(tmp_path), "art_semgrep")

    assert artifact is not None
    assert "sk-phase7-secret-value-123456" not in artifact["stdout"]
    assert "[REDACTED]" in artifact["stdout"]


def test_findings_endpoint_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/api/scans/missing/findings")

    assert response.status_code == 401


def test_findings_endpoint_filters_owned_scan(tmp_path):
    suffix = uuid4().hex[:8]
    store = PostgresStore()

    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"email": f"phase7-{suffix}@example.com", "password": "correct horse battery staple"})
        token = login.json()["token"]
        user_id = login.json()["user"]["id"]
        scan = sample_scan(tmp_path)
        store.save_scan(scan, user_id)
        response = client.get(
            f"/api/scans/{scan.id}/findings?severity=critical&page_size=5",
            headers={"authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert response.json()["total"] == 1
