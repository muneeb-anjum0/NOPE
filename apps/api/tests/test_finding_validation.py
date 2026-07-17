from pathlib import Path

from nope_api.finding_validation import validate_findings, validation_counts
from nope_api.models import Confidence, Evidence, Finding, Severity


def authz_finding(path: str, *, line: int = 1) -> Finding:
    return Finding(
        fingerprint=f"authz-{path}-{line}",
        scanner="NOPE rules",
        original_rule_id="NOPE-AUTHZ-001",
        nope_rule_id="NOPE-AUTHZ-001",
        title="Database lookup by ID may lack owner scope",
        description="A database lookup by ID is performed without enforcing owner or tenant scope.",
        severity=Severity.high,
        confidence=Confidence.medium,
        category="Authorization",
        affected_file=path,
        start_line=line,
        end_line=line,
        scanner_sources=["NOPE rules"],
        evidence=[
            Evidence(
                source="NOPE-AUTHZ-001",
                file=path,
                line=line,
                end_line=line,
                snippet="select(attrs, fn, css_hash, classes, styles, flags, is_rich) {",
                message="Matched NOPE rule NOPE-AUTHZ-001.",
            )
        ],
        remediation="Filter records by authenticated owner or tenant.",
    )


def test_generated_authorization_candidate_is_not_promoted(tmp_path: Path):
    generated = tmp_path / "apps" / "web" / ".svelte-kit" / "output" / "server" / "chunks"
    generated.mkdir(parents=True)
    (generated / "server.js").write_text(
        "function select(attrs, fn, css_hash, classes, styles, flags, is_rich) {\n"
        "  return attrs;\n"
        "}\n",
        encoding="utf-8",
    )

    promoted, decisions = validate_findings(
        [authz_finding("apps/web/.svelte-kit/output/server/chunks/server.js")],
        tmp_path,
    )

    assert promoted == []
    counts = validation_counts(decisions)
    assert counts["needs_context"] == 1
    assert "generated" in decisions[0]["reasons"][0].lower()


def test_source_authorization_context_is_promoted(tmp_path: Path):
    route = tmp_path / "app" / "api" / "invoices" / "[id]"
    route.mkdir(parents=True)
    (route / "route.ts").write_text(
        "export async function GET(request, { params }) {\n"
        "  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n"
        "  return Response.json(invoice);\n"
        "}\n",
        encoding="utf-8",
    )

    promoted, decisions = validate_findings(
        [authz_finding("app/api/invoices/[id]/route.ts", line=2)],
        tmp_path,
    )

    assert len(promoted) == 1
    assert promoted[0].verification_state == "context_validated"
    assert any(evidence.source == "NOPE evidence gate" for evidence in promoted[0].evidence)
    assert validation_counts(decisions)["promoted"] == 1


def test_source_authorization_with_owner_scope_is_rejected(tmp_path: Path):
    route = tmp_path / "app" / "api" / "invoices" / "[id]"
    route.mkdir(parents=True)
    (route / "route.ts").write_text(
        "export async function GET(request, { params }) {\n"
        "  const session = await requireUser(request);\n"
        "  const invoice = await prisma.invoice.findFirst({\n"
        "    where: { id: params.id, ownerId: session.user.id },\n"
        "  });\n"
        "  return Response.json(invoice);\n"
        "}\n",
        encoding="utf-8",
    )

    promoted, decisions = validate_findings(
        [authz_finding("app/api/invoices/[id]/route.ts", line=3)],
        tmp_path,
    )

    assert promoted == []
    counts = validation_counts(decisions)
    assert counts["rejected"] == 1
    assert "owner" in decisions[0]["reasons"][0].lower()


def test_secret_in_generated_output_is_still_promoted(tmp_path: Path):
    generated = tmp_path / "dist"
    generated.mkdir()
    (generated / "bundle.js").write_text("const apiKey = 'sk_live_1234567890';\n", encoding="utf-8")
    finding = Finding(
        fingerprint="secret-generated",
        scanner="NOPE rules",
        original_rule_id="NOPE-SECRET-001",
        title="Potential hardcoded secret",
        description="Secret-like assignment found.",
        severity=Severity.critical,
        confidence=Confidence.high,
        category="Secrets",
        affected_file="dist/bundle.js",
        start_line=1,
        end_line=1,
        scanner_sources=["NOPE rules"],
        evidence=[
            Evidence(
                source="NOPE-SECRET-001",
                file="dist/bundle.js",
                line=1,
                end_line=1,
                snippet="const apiKey = 'sk_live_1234567890';",
                message="Secret-like assignment found.",
            )
        ],
        remediation="Move the secret to managed secret storage and rotate it.",
    )

    promoted, decisions = validate_findings([finding], tmp_path)

    assert len(promoted) == 1
    assert validation_counts(decisions)["promoted"] == 1
