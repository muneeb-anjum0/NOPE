from pathlib import Path

from nope_api.finding_quality import apply_finding_quality_gate
from nope_api.models import (
    Confidence,
    Evidence,
    Finding,
    FindingDisposition,
    Reachability,
    Severity,
)
from nope_api.semantic_validation import build_semantic_context, classify_execution_context


def observation(
    file: str,
    *,
    title: str,
    category: str = "Secrets",
    rule: str = "NOPE-SEMANTIC",
    route: str | None = None,
) -> Finding:
    return Finding(
        scanner="NOPE Rules v2",
        original_rule_id=rule,
        fingerprint=f"{file}:{rule}:{title}",
        title=title,
        description=title,
        severity=Severity.high,
        confidence=Confidence.high,
        category=category,
        affected_file=file,
        affected_route=route,
        evidence=[Evidence(source="test", file=file, message=title)],
        remediation="Fix it.",
        verification_state="rules_v2_promoted",
    )


def classify(tmp_path: Path, finding: Finding):
    confirmed, observations, _ = apply_finding_quality_gate([finding], tmp_path)
    return confirmed, observations[0]


def write(tmp_path: Path, rel: str, text: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_process_env_read_without_sink_is_rejected_but_response_flow_promotes(tmp_path):
    write(tmp_path, "server/config.ts", "export const token = process.env.GITHUB_TOKEN;")
    _, safe = classify(
        tmp_path, observation("server/config.ts", title="Environment secret exposure")
    )
    assert safe.disposition == FindingDisposition.rejected
    assert safe.disposition_reason_codes == ["REJECTED_NO_EXPOSURE_SINK"]

    write(
        tmp_path,
        "app/api/debug/route.ts",
        "export function GET() { const token = process.env.GITHUB_TOKEN; "
        "return Response.json({token}); }",
    )
    confirmed, unsafe = classify(
        tmp_path,
        observation(
            "app/api/debug/route.ts", title="Environment secret exposure", route="/api/debug"
        ),
    )
    assert confirmed and unsafe.disposition == FindingDisposition.confirmed
    assert unsafe.disposition_reason_codes == ["PROMOTED_VERIFIED_SOURCE_SINK"]


def test_public_configuration_is_not_secret_but_sensitive_public_variable_is(tmp_path):
    write(
        tmp_path,
        "app/api/site/route.ts",
        "export function GET() { const value = process.env.NEXT_PUBLIC_SITE_URL; "
        "return Response.json({value}); }",
    )
    _, safe = classify(
        tmp_path, observation("app/api/site/route.ts", title="Environment secret exposure")
    )
    assert safe.disposition_reason_codes == ["REJECTED_PUBLIC_CONFIG_NOT_SECRET"]

    write(
        tmp_path,
        "app/api/leak/route.ts",
        "export function GET() { const value = process.env.NEXT_PUBLIC_DATABASE_PASSWORD; "
        "return Response.json({value}); }",
    )
    confirmed, unsafe = classify(
        tmp_path, observation("app/api/leak/route.ts", title="Environment secret exposure")
    )
    assert confirmed and unsafe.data_sensitivity.value == "CRITICAL_SECRET"


def test_type_schema_and_frontend_client_cannot_prove_server_route(tmp_path):
    write(
        tmp_path, "types/preview.d.ts", "export interface PreviewResponse { environment: string }"
    )
    _, typed = classify(
        tmp_path,
        observation("types/preview.d.ts", title="Preview endpoint exposed", category="Staging"),
    )
    assert typed.disposition_reason_codes == ["REJECTED_TYPE_ONLY_CONTEXT"]

    write(
        tmp_path,
        "components/api-client.tsx",
        '"use client"; export const preview = () => fetch("/api/preview");',
    )
    _, client = classify(
        tmp_path,
        observation(
            "components/api-client.tsx", title="Preview endpoint exposed", category="Staging"
        ),
    )
    assert client.disposition_reason_codes == ["REJECTED_NO_SERVER_ROUTE"]


def test_test_fixture_fake_secret_is_rejected(tmp_path):
    write(
        tmp_path,
        "tests/security.test.ts",
        'const token = "ghp_should_not_escape"; console.log(token);',
    )
    _, result = classify(
        tmp_path, observation("tests/security.test.ts", title="Secret token exposure")
    )
    assert result.disposition_reason_codes == ["REJECTED_TEST_ONLY_CONTEXT"]


def test_vite_bind_with_compose_loopback_is_not_public(tmp_path):
    write(tmp_path, "vite.config.ts", "export default { server: { host: '0.0.0.0', port: 4173 } };")
    write(
        tmp_path,
        "docker-compose.yml",
        "services:\n  ui:\n    ports:\n      - '127.0.0.1:4173:4173'\n",
    )
    context = build_semantic_context(tmp_path)
    assert context.reachability == Reachability.host_loopback
    assert any("loopback-only" in item.lower() for item in context.reachability_evidence)


def test_public_debug_route_promotes_and_loopback_debug_route_rejects(tmp_path):
    write(
        tmp_path,
        "app/api/debug/route.ts",
        "export function GET() { return Response.json({ debug: true }); }",
    )
    write(tmp_path, "docker-compose.yml", "services:\n  api:\n    ports:\n      - '8000:8000'\n")
    confirmed, public = classify(
        tmp_path,
        observation(
            "app/api/debug/route.ts",
            title="Debug endpoint exposed",
            category="Staging",
            route="/api/debug",
        ),
    )
    assert confirmed and public.disposition_reason_codes == ["PROMOTED_VERIFIED_PUBLIC_ROUTE"]

    write(
        tmp_path,
        "docker-compose.yml",
        "services:\n  api:\n    ports:\n      - '127.0.0.1:8000:8000'\n",
    )
    confirmed, loopback = classify(
        tmp_path,
        observation(
            "app/api/debug/route.ts",
            title="Debug endpoint exposed",
            category="Staging",
            route="/api/debug",
        ),
    )
    assert not confirmed and loopback.disposition_reason_codes == ["REJECTED_LOOPBACK_ONLY"]


def test_effective_auth_rejects_idor_but_unprotected_resource_flow_promotes(tmp_path):
    write(
        tmp_path,
        "app/api/items/[id]/route.ts",
        "export async function GET(req) { const session = await requireAuth(); "
        "return db.item.findFirst({where:{id:req.params.id,userId:session.user.id}}); }",
    )
    _, safe = classify(
        tmp_path,
        observation(
            "app/api/items/[id]/route.ts",
            title="IDOR authorization gap",
            category="Authorization",
            route="/api/items/{id}",
        ),
    )
    assert safe.disposition_reason_codes == ["REJECTED_EFFECTIVE_AUTH_PRESENT"]

    write(
        tmp_path,
        "app/api/items/[id]/route.ts",
        "export async function GET(req) { return Response.json("
        "await db.item.findUnique({where:{id:req.params.id}})); }",
    )
    confirmed, unsafe = classify(
        tmp_path,
        observation(
            "app/api/items/[id]/route.ts",
            title="IDOR authorization gap",
            category="Authorization",
            route="/api/items/{id}",
        ),
    )
    assert confirmed and unsafe.disposition_reason_codes == ["PROMOTED_VERIFIED_AUTHZ_GAP"]


def test_execution_context_classification_is_multi_label_and_unknown_stays_unknown():
    assert {
        item.value
        for item in classify_execution_context("playwright.config.ts", "export default {}")
    } >= {"TEST", "E2E_TEST", "CONFIGURATION"}
    assert {
        item.value
        for item in classify_execution_context("types/model.d.ts", "interface Model { id: string }")
    } == {"TYPE_ONLY"}
    assert {
        item.value for item in classify_execution_context("blob.unknown", "preview internal secret")
    } == {"UNKNOWN"}
