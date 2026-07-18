import asyncio
import json
from pathlib import Path

import pytest

from nope_api import benchmarks
from nope_api.benchmarks import (
    REQUIRED_BENCHMARK_CATEGORIES,
    compare_findings,
    validate_expected_manifest,
    validate_fixture_manifest,
)
from nope_api.models import AIReview, Confidence, Finding, Scan, ScanMode, ScannerRun, Severity
from nope_api.rules_engine import dedupe_findings, run_rules


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "benchmarks" / "fixtures" / "nope-benchmark-v1"
EXPECTED = ROOT / "benchmarks" / "expected" / "nope-benchmark-v1.expected.json"


def finding(title: str, category: str, file: str, rule_id: str = "NOPE-TEST") -> Finding:
    return Finding(
        fingerprint=f"{rule_id}:{file}",
        scanner="NOPE rules",
        original_rule_id=rule_id,
        title=title,
        description=title,
        severity=Severity.high,
        confidence=Confidence.high,
        category=category,
        affected_file=file,
        remediation="Fix the benchmark issue.",
        scanner_sources=["NOPE rules"],
    )


def test_phase12_fixture_declares_every_required_category():
    assert validate_fixture_manifest(FIXTURE) == []
    manifest = benchmarks.load_json(FIXTURE / "benchmark-manifest.json")
    categories = {item["id"] for item in manifest["categories"]}
    assert set(REQUIRED_BENCHMARK_CATEGORIES) <= categories
    assert {item["id"] for item in manifest["negative_controls"]} >= {
        "safe-parameterized-sql",
        "safe-authorization-scope",
        "safe-consent-tracker",
        "safe-placeholder-secret",
    }


def test_phase12_expected_output_is_versioned_and_machine_readable():
    expected = benchmarks.load_json(EXPECTED)
    assert expected["benchmark_id"] == "nope-benchmark-v1"
    assert expected["version"] >= 2
    assert validate_expected_manifest(expected) == []
    expected_ids = {item["id"] for item in expected["expected_findings"]}
    assert set(REQUIRED_BENCHMARK_CATEGORIES) <= expected_ids
    assert all("severity" in item and "confidence" in item and "cwe" in item for item in expected["expected_findings"])


@pytest.mark.parametrize("category_id", REQUIRED_BENCHMARK_CATEGORIES)
def test_phase12_each_required_category_has_a_detection_contract(category_id):
    manifest = benchmarks.load_json(FIXTURE / "benchmark-manifest.json")
    expected = benchmarks.load_json(EXPECTED)
    manifest_items = {item["id"]: item for item in manifest["categories"]}
    expected_items = {item["id"]: item for item in expected["expected_findings"]}

    assert category_id in manifest_items
    assert category_id in expected_items
    assert (FIXTURE / manifest_items[category_id]["file"]).exists()
    assert expected_items[category_id]["match"]["any"]
    assert expected_items[category_id]["expected_scanner"]


def test_phase12_nope_rules_detect_all_rule_backed_categories():
    expected = benchmarks.load_json(EXPECTED)
    rule_expected = {
        **expected,
        "expected_findings": [
            item for item in expected["expected_findings"] if item["expected_scanner"] == "NOPE rules"
        ],
    }
    scan = Scan(mode=ScanMode.repository)
    scan.findings = run_rules(FIXTURE)

    metrics = compare_findings(scan, rule_expected)

    assert metrics["false_negatives"] == []
    assert metrics["known_false_negatives"] == []
    assert metrics["recall"] == 1.0


def test_phase12_negative_controls_are_not_flagged_by_nope_rules():
    findings = run_rules(FIXTURE)
    files = {finding.affected_file for finding in findings}
    assert not any(str(file or "").startswith("safe-controls/") for file in files)


def test_compare_findings_tracks_true_positive_false_positive_and_known_false_negative():
    expected = {
        "expected_findings": [
            {"id": "secret", "category": "Secrets", "file": "src/secret.ts", "match": {"any": ["secret"]}},
            {
                "id": "tracker-before-consent",
                "category": "Privacy",
                "file": "src/tracker.tsx",
                "known_false_negative": True,
                "match": {"any": ["tracker"]},
            },
        ]
    }
    scan = Scan(mode=ScanMode.repository)
    scan.findings = [
        finding("Potential hardcoded secret", "Secrets", "src/secret.ts", "NOPE-SEC-001"),
        finding("Unexpected debug endpoint", "Staging", "src/debug.ts", "NOPE-DBG"),
    ]
    metrics = compare_findings(scan, expected)
    assert len(metrics["true_positives"]) == 1
    assert len(metrics["false_positives"]) == 1
    assert len(metrics["known_false_negatives"]) == 1
    assert metrics["false_negatives"] == []
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5


def test_compare_findings_is_deterministic_for_same_scan():
    expected = {
        "expected_findings": [
            {"id": "secret", "category": "Secrets", "file": "src/secret.ts", "match": {"any": ["secret"]}},
        ]
    }
    scan = Scan(mode=ScanMode.repository)
    scan.findings = [finding("Potential hardcoded secret", "Secrets", "src/secret.ts", "NOPE-SEC-001")]

    first = compare_findings(scan, expected)
    second = compare_findings(scan, expected)

    assert first == second


def test_phase12_distinct_rules_on_same_line_are_not_deduped():
    first = finding("Debug endpoint exposes runtime internals", "Staging", "scripts/build.js", "NOPE-DEBUG-001")
    second = finding("Build script executes caller-controlled shell", "CI/CD", "scripts/build.js", "NOPE-BUILD-001")
    for item in (first, second):
        item.start_line = 3
        item.end_line = 3

    merged = dedupe_findings([first, second])

    assert len(merged) == 2
    assert {item.original_rule_id for item in merged} == {"NOPE-DEBUG-001", "NOPE-BUILD-001"}


def write_tiny_expected(tmp_path: Path) -> Path:
    expected = {
        "benchmark_id": "tiny-benchmark",
        "version": 1,
        "expected_findings": [
            {
                "id": "backend-hardcoded-secret",
                "category": "Secrets",
                "file": "src/config/secrets.ts",
                "line": 1,
                "severity": "high",
                "confidence": "high",
                "cwe": "CWE-798",
                "owasp": "A02:2021-Cryptographic Failures",
                "expected_scanner": "NOPE rules",
                "qwen_enrichment_expected": True,
                "dedupe_expected": True,
                "match": {"any": ["secret", "NOPE-SEC-001"]},
            }
        ],
    }
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(expected), encoding="utf-8")
    return path


def test_run_benchmark_fails_when_scanner_is_unavailable(monkeypatch, tmp_path):
    async def fake_run_repository_scan(scan, root, settings):
        scan.status = "partial"
        scan.findings = [finding("Potential hardcoded secret", "Secrets", "src/config/secrets.ts", "NOPE-SEC-001")]
        scan.scanner_runs = [ScannerRun(scanner="Semgrep", status="failed", message="scanner unavailable")]
        return scan

    monkeypatch.setattr(benchmarks, "run_repository_scan", fake_run_repository_scan)
    result = asyncio.run(benchmarks.run_benchmark(FIXTURE, write_tiny_expected(tmp_path), "scanner-only"))

    assert result["status"] == "failed"
    assert result["scan"]["failed_scanners"][0]["scanner"] == "Semgrep"
    assert "unavailable" in result["scan"]["failed_scanners"][0]["message"]


def test_run_benchmark_fails_when_scanner_times_out(monkeypatch, tmp_path):
    async def fake_run_repository_scan(scan, root, settings):
        scan.status = "partial"
        scan.findings = [finding("Potential hardcoded secret", "Secrets", "src/config/secrets.ts", "NOPE-SEC-001")]
        scan.scanner_runs = [ScannerRun(scanner="Trivy", status="failed", message="scanner timeout after 300s")]
        return scan

    monkeypatch.setattr(benchmarks, "run_repository_scan", fake_run_repository_scan)
    result = asyncio.run(benchmarks.run_benchmark(FIXTURE, write_tiny_expected(tmp_path), "scanner-only"))

    assert result["status"] == "failed"
    assert result["scan"]["failed_scanners"][0]["scanner"] == "Trivy"
    assert "timeout" in result["scan"]["failed_scanners"][0]["message"]


def test_run_benchmark_preserves_deterministic_pass_when_qwen_is_unavailable(monkeypatch, tmp_path):
    expected = benchmarks.load_json(EXPECTED)

    async def fake_run_repository_scan(scan, root, settings):
        scan.status = "completed"
        scan.findings = [
            finding(str(item["match"]["any"][0]), str(item["category"]), str(item["file"]), str(item["id"]))
            for item in expected["expected_findings"]
        ]
        scan.scanner_runs = [ScannerRun(scanner="NOPE rules", status="passed", findings_count=len(scan.findings))]
        scan.ai_review = AIReview(status="Failed", provider="qwen", model="local", message="Qwen unavailable")
        return scan

    monkeypatch.setattr(benchmarks, "run_repository_scan", fake_run_repository_scan)
    result = asyncio.run(benchmarks.run_benchmark(FIXTURE, EXPECTED, "scanner-plus-qwen"))

    assert result["status"] == "passed"
    assert result["qwen_contribution"]["status"] == "Failed"
    assert result["metrics"]["recall"] == 1.0


def test_run_benchmark_emits_result_schema(monkeypatch):
    async def fake_run_repository_scan(scan, root, settings):
        scan.status = "completed"
        scan.findings = [
            finding("Potential hardcoded secret", "Secrets", "src/config/secrets.ts", "NOPE-SEC-001"),
            finding("Database lookup by ID may lack owner scope", "Authorization", "src/api/invoices.ts", "NOPE-AUTHZ-001"),
        ]
        scan.scanner_runs = [ScannerRun(scanner="NOPE rules", status="passed", findings_count=2)]
        scan.coverage_percent = 10
        scan.score = 80
        return scan

    monkeypatch.setattr(benchmarks, "run_repository_scan", fake_run_repository_scan)
    result = asyncio.run(benchmarks.run_benchmark(FIXTURE, EXPECTED, "scanner-only"))
    assert result["schema_version"] == 1
    assert result["mode"] == "scanner-only"
    assert result["manifest_errors"] == []
    assert result["metrics"]["expected_findings"] >= len(REQUIRED_BENCHMARK_CATEGORIES)
    assert result["scan"]["resource_use"]["process_cpu_ms"] >= 0
    assert result["qwen_contribution"]["mode"] == "scanner-only"
