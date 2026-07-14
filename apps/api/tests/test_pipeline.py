from pathlib import Path

from nope_api.attack_surface import build_attack_surface
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


def test_dedupe_keeps_unique_fingerprints():
    root = Path(__file__).parents[1] / "tests" / "fixtures" / "vulnerable-next"
    findings = run_rules(root)
    assert len(dedupe_findings(findings + findings)) == len(dedupe_findings(findings))


def test_score_decreases_for_findings():
    root = Path(__file__).parents[1] / "tests" / "fixtures" / "vulnerable-next"
    findings = run_rules(root)
    assert calculate_score(findings, []) < 100
