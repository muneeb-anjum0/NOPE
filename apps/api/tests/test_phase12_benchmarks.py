import asyncio
from pathlib import Path

from nope_api import benchmarks
from nope_api.benchmarks import (
    REQUIRED_BENCHMARK_CATEGORIES,
    compare_findings,
    validate_expected_manifest,
    validate_fixture_manifest,
)
from nope_api.models import Confidence, Finding, Scan, ScanMode, ScannerRun, Severity
from nope_api.rules_engine import run_rules


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
