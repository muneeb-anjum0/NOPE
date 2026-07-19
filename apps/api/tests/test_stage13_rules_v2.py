from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from nope_api.auth import clear_login_rate_limits
from nope_api.main import app
from nope_api.models import Confidence, Evidence, Finding, Scan, ScanMode, Severity
from nope_api.reports import report_json, report_markdown, report_sarif
from nope_api.rules_v2 import generate_candidates, list_rule_inventory, run_rules_v2, validate_rule_catalog
from nope_api.storage import PostgresStore


def _login(client: TestClient, prefix: str) -> dict:
    clear_login_rate_limits()
    suffix = uuid4().hex[:8]
    response = client.post(
        "/api/auth/login",
        json={"email": f"{prefix}-{suffix}@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return response.json()


def _auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def test_rules_v2_catalog_is_first_class_and_large_enough():
    summary = validate_rule_catalog()
    inventory = list_rule_inventory()

    assert summary["rule_count"] >= 100
    assert summary["families"]["legacy-upgraded"] >= 30
    assert any(rule["rule_id"] == "NOPE-CORR-IDOR-001" for rule in inventory["rules"])
    assert any(rule["rule_id"] == "NOPE-SUPABASE-RLS-008" for rule in inventory["rules"])
    assert all(rule["version"].count(".") == 2 for rule in inventory["rules"])
    assert all(rule["evidence_requirements"] for rule in inventory["rules"])


def test_rules_v2_promotes_conclusive_public_secret_and_reports_it(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "page.tsx").write_text(
        'export const NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY = "sk_live_stage13_secret_value_123456789";\n',
        encoding="utf-8",
    )
    scan = Scan(id=f"scan_stage13_rules_{uuid4().hex[:8]}", mode=ScanMode.repository, repository_name="repo.zip")

    promoted, payload = run_rules_v2(scan, repo, [])
    scan.rules_v2 = payload
    scan.findings = promoted

    assert payload["coverage"]["candidate_count"] >= 1
    assert payload["coverage"]["promoted"] >= 1
    assert any(finding.nope_rule_id in {"NOPE-NEXT-DATA-001", "NOPE-CORR-SECRET-001"} for finding in promoted)
    assert all(finding.source_metadata.get("rules_v2") is True for finding in promoted)
    assert report_json(scan)["rules_v2"]["coverage"]["promoted"] >= 1
    assert "Rules v2" in report_markdown(scan)
    sarif = report_sarif(scan)
    assert sarif["runs"][0]["properties"]["rules_v2"]["version"] == payload["version"]


def test_rules_v2_withholds_weak_authorization_candidate_until_owner_context_exists(tmp_path: Path):
    repo = tmp_path / "repo"
    route = repo / "app" / "api" / "invoices" / "[id]"
    route.mkdir(parents=True)
    (route / "route.ts").write_text(
        """
        import { auth } from "@clerk/nextjs/server";
        export async function GET(req, { params }) {
          const user = auth();
          return prisma.invoice.findUnique({ where: { id: params.id } });
        }
        """,
        encoding="utf-8",
    )
    scan = Scan(id=f"scan_stage13_withheld_{uuid4().hex[:8]}", mode=ScanMode.repository, repository_name="repo.zip")

    promoted, payload = run_rules_v2(scan, repo, [])

    assert promoted == []
    assert any(candidate["rule_id"] == "NOPE-PRISMA-001" for candidate in payload["candidates"])
    assert any(
        decision["rule_id"] == "NOPE-PRISMA-001" and decision["result"] == "withheld"
        for decision in payload["decisions"]
    )


def test_rules_v2_external_scanner_evidence_correlates_without_losing_original_finding(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "route.ts"
    source.write_text("export const token = process.env.SECRET_TOKEN;\n", encoding="utf-8")
    scan = Scan(id=f"scan_stage13_external_{uuid4().hex[:8]}", mode=ScanMode.repository, repository_name="repo.zip")
    external = Finding(
        scanner="Gitleaks",
        original_rule_id="generic-api-key",
        fingerprint="external-secret-stage13",
        title="Potential hardcoded secret",
        description="External scanner found a secret-like token.",
        severity=Severity.high,
        confidence=Confidence.high,
        category="Secrets",
        affected_file="route.ts",
        start_line=1,
        remediation="Remove the secret and rotate it.",
        scanner_sources=["Gitleaks"],
        evidence=[Evidence(source="Gitleaks", file="route.ts", line=1, message="Secret-like token.")],
    )

    promoted, payload = run_rules_v2(scan, repo, [external])

    assert any(finding.nope_rule_id == "NOPE-CORR-SECRET-001" for finding in promoted)
    assert payload["coverage"]["by_family"]["correlation"]["promoted"] >= 1
    correlated = next(finding for finding in promoted if finding.nope_rule_id == "NOPE-CORR-SECRET-001")
    assert "Gitleaks:generic-api-key" in correlated.source_metadata["scanner_references"]


def test_rules_v2_api_is_authorized_paginated_and_filterable():
    suffix = uuid4().hex[:8]
    store = PostgresStore()
    with TestClient(app) as client:
        owner = _login(client, "stage13-rules-owner")
        other = _login(client, "stage13-rules-other")
        project = store.create_project(f"Rules v2 {suffix}", "rules-v2.zip", None, owner["user"]["id"])
        scan = Scan(
            id=f"scan_stage13_api_{suffix}",
            project_id=project.id,
            mode=ScanMode.repository,
            status="completed",
            repository_name="rules-v2.zip",
            rules_v2={
                "version": "rules-v2.test",
                "catalog": {"rule_count": 101},
                "coverage": {"candidate_count": 1, "promoted": 0, "withheld": 1, "rejected": 0, "needs_manual_review": 0, "not_applicable": 0},
                "metrics": {"total_ms": 4},
                "failures": [],
                "candidates": [
                    {
                        "candidate_id": "rv2_candidate_api",
                        "rule_id": "NOPE-PRISMA-001",
                        "rule_version": "2.0.0",
                        "family": "prisma",
                        "preliminary_severity": "high",
                        "preliminary_confidence": "medium",
                        "file": "app/api/route.ts",
                    }
                ],
                "decisions": [
                    {
                        "candidate_id": "rv2_candidate_api",
                        "rule_id": "NOPE-PRISMA-001",
                        "rule_version": "2.0.0",
                        "result": "withheld",
                        "confidence": "medium",
                        "evidence_strength": "incomplete",
                        "reason": "Missing owner scope.",
                    }
                ],
            },
        )
        store.save_scan(scan, owner["user"]["id"])

        summary = client.get(f"/api/scans/{scan.id}/rules-v2", headers=_auth(owner["token"]))
        candidates = client.get(
            f"/api/scans/{scan.id}/rules-v2/candidates?result=withheld&page_size=1",
            headers=_auth(owner["token"]),
        )
        detail = client.get(f"/api/scans/{scan.id}/rules-v2/candidates/rv2_candidate_api", headers=_auth(owner["token"]))
        forbidden = client.get(f"/api/scans/{scan.id}/rules-v2", headers=_auth(other["token"]))

    assert summary.status_code == 200
    assert summary.json()["coverage"]["withheld"] == 1
    assert candidates.status_code == 200
    assert candidates.json()["total"] == 1
    assert candidates.json()["items"][0]["decision"]["result"] == "withheld"
    assert detail.status_code == 200
    assert detail.json()["candidate"]["rule_id"] == "NOPE-PRISMA-001"
    assert forbidden.status_code == 404


def test_rules_v2_candidate_ids_are_deterministic_for_same_evidence(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "client.ts").write_text('const NEXT_PUBLIC_API_KEY = "sk_stage13_repeatable_123456";\n', encoding="utf-8")
    first_scan = Scan(id="scan_stage13_repeat_a", mode=ScanMode.repository)
    second_scan = Scan(id="scan_stage13_repeat_b", mode=ScanMode.repository)

    first = generate_candidates(first_scan, repo, [])
    second = generate_candidates(second_scan, repo, [])

    first_keys = {(candidate.rule_id, candidate.file, candidate.line, candidate.source_type) for candidate in first}
    second_keys = {(candidate.rule_id, candidate.file, candidate.line, candidate.source_type) for candidate in second}
    assert first_keys == second_keys
