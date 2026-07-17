from pathlib import Path

from nope_api.attack_surface import build_attack_surface, build_code_graph
from nope_api.rules_engine import dedupe_findings, run_rules
from nope_api.scoring import calculate_score
from nope_api.stack_detector import detect_stack


def test_stack_detector_and_rules_find_vulnerable_fixture():
    root = Path(__file__).parents[1] / "tests" / "fixtures" / "vulnerable-next"
    stack = detect_stack(root)
    assert any(item.technology == "Next.js" for item in stack)
    findings = run_rules(root)
    assert any(finding.category == "Secrets" for finding in findings)
    assert any(finding.category == "Authorization" for finding in findings)


def test_attack_surface_extracts_next_api_route():
    root = Path(__file__).parents[1] / "tests" / "fixtures" / "vulnerable-next"
    surface = build_attack_surface(root)
    assert any(item.route == "/invoices/:id" for item in surface)


def test_attack_surface_extracts_sveltekit_routes(tmp_path):
    route_dir = tmp_path / "apps" / "web" / "src" / "routes" / "app" / "invoices" / "[id]"
    route_dir.mkdir(parents=True)
    (route_dir / "+server.ts").write_text(
        """
        import { json } from '@sveltejs/kit';

        export async function GET({ params, locals }) {
          const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });
          return json(invoice);
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "apps" / "web" / "src" / "routes" / "app" / "+page.svelte").write_text(
        "<script>export let data;</script>",
        encoding="utf-8",
    )
    (tmp_path / "apps" / "web" / "src" / "routes" / "+page.svelte").write_text(
        "<main>Home</main>",
        encoding="utf-8",
    )

    surface = build_attack_surface(tmp_path)
    graph = build_code_graph(tmp_path, surface)

    api_route = next(item for item in surface if item.route == "/app/invoices/:id")
    assert api_route.method == "GET"
    assert "params" in api_route.input_sources
    assert "prisma" in api_route.database_access
    assert any(item.route == "/" and item.method == "PAGE" for item in surface)
    assert any(item.route == "/app" and item.method == "PAGE" for item in surface)
    assert graph.nodes
    assert graph.edges


def test_dedupe_keeps_unique_fingerprints():
    root = Path(__file__).parents[1] / "tests" / "fixtures" / "vulnerable-next"
    findings = run_rules(root)
    assert len(dedupe_findings(findings + findings)) == len(dedupe_findings(findings))


def test_score_decreases_for_findings():
    root = Path(__file__).parents[1] / "tests" / "fixtures" / "vulnerable-next"
    findings = run_rules(root)
    assert calculate_score(findings, []) < 100
