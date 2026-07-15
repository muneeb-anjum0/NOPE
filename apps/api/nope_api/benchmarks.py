import argparse
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nope_api.config import Settings, get_settings
from nope_api.models import Finding, Scan, ScanMode
from nope_api.scan_engine import run_repository_scan


REQUIRED_BENCHMARK_CATEGORIES = [
    "hardcoded-secret",
    "frontend-secret",
    "sql-injection",
    "nosql-injection",
    "command-injection",
    "xss",
    "unsafe-html",
    "ssrf",
    "path-traversal",
    "file-upload",
    "idor",
    "missing-tenant-scope",
    "frontend-only-authorization",
    "insecure-cors",
    "missing-rate-limit",
    "ai-cost-abuse",
    "vulnerable-dependency",
    "debug-endpoint",
    "public-source-map",
    "unsafe-supabase-rls",
    "public-storage-bucket",
    "tracker-before-consent",
]


@dataclass
class BenchmarkResources:
    wall_ms: int
    process_cpu_ms: int
    max_rss_bytes: int | None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_fixture_manifest(fixture: Path) -> list[str]:
    manifest_path = fixture / "benchmark-manifest.json"
    if not manifest_path.exists():
        return ["Missing benchmark-manifest.json."]
    manifest = load_json(manifest_path)
    categories = {str(item.get("id")) for item in manifest.get("categories", [])}
    missing = [category for category in REQUIRED_BENCHMARK_CATEGORIES if category not in categories]
    problems = [f"Missing fixture category: {category}" for category in missing]
    for item in manifest.get("categories", []):
        rel = item.get("file")
        if rel and not (fixture / str(rel)).exists():
            problems.append(f"Fixture file is missing for {item.get('id')}: {rel}")
    return problems


def _settings_for_mode(settings: Settings, mode: str) -> Settings:
    updates: dict[str, Any] = {"sandbox_enabled": False}
    if mode == "scanner-only":
        updates["ai_provider"] = "none"
    return settings.model_copy(update=updates)


def finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "scanner": finding.scanner,
        "scanner_sources": finding.scanner_sources,
        "rule_id": finding.original_rule_id or finding.nope_rule_id,
        "file": finding.affected_file,
        "line": finding.start_line,
        "package": finding.package,
        "cve": finding.cve,
        "fix_available": finding.fix_available,
    }


def _text_for_match(finding: Finding) -> str:
    parts = [
        finding.title,
        finding.description,
        finding.category,
        finding.affected_file,
        finding.original_rule_id,
        finding.nope_rule_id,
        finding.scanner,
        finding.package,
        finding.cve,
    ]
    return " ".join(str(part or "") for part in parts).lower()


def _matches_expected(finding: Finding, expected: dict[str, Any]) -> bool:
    text = _text_for_match(finding)
    category = expected.get("category")
    if category and str(category).lower() != finding.category.lower():
        return False
    file_hint = expected.get("file")
    if file_hint and str(file_hint).lower() not in str(finding.affected_file or "").lower():
        return False
    all_terms = [str(term).lower() for term in expected.get("match", {}).get("all", [])]
    any_terms = [str(term).lower() for term in expected.get("match", {}).get("any", [])]
    return all(term in text for term in all_terms) and (not any_terms or any(term in text for term in any_terms))


def compare_findings(scan: Scan, expected: dict[str, Any]) -> dict[str, Any]:
    findings = scan.findings
    matched_fingerprints: set[str] = set()
    true_positives: list[dict[str, Any]] = []
    known_false_negatives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    for item in expected.get("expected_findings", []):
        match = next((finding for finding in findings if finding.fingerprint not in matched_fingerprints and _matches_expected(finding, item)), None)
        if match:
            matched_fingerprints.add(match.fingerprint)
            true_positives.append({"expected_id": item["id"], "finding": finding_payload(match)})
        elif item.get("known_false_negative"):
            known_false_negatives.append(item)
        else:
            false_negatives.append(item)
    false_positives = [finding_payload(finding) for finding in findings if finding.fingerprint not in matched_fingerprints]
    by_scanner: dict[str, int] = {}
    for finding in findings:
        for source in finding.scanner_sources or [finding.scanner or "unknown"]:
            by_scanner[source] = by_scanner.get(source, 0) + 1
    return {
        "expected_findings": len(expected.get("expected_findings", [])),
        "actual_findings": len(findings),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "known_false_negatives": known_false_negatives,
        "false_negatives": false_negatives,
        "scanner_source": by_scanner,
        "fix_verification": {
            "fix_available_findings": sum(1 for finding in findings if finding.fix_available),
            "verified_fixes": sum(1 for finding in findings if finding.verified),
        },
    }


def _resource_usage(start_wall: float, start_cpu: float) -> BenchmarkResources:
    max_rss_bytes = None
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF)
        max_rss_bytes = int(usage.ru_maxrss) * 1024
    except Exception:
        max_rss_bytes = None
    return BenchmarkResources(
        wall_ms=round((time.perf_counter() - start_wall) * 1000),
        process_cpu_ms=round((time.process_time() - start_cpu) * 1000),
        max_rss_bytes=max_rss_bytes,
    )


async def run_benchmark(fixture: Path, expected_path: Path, mode: str, settings: Settings | None = None) -> dict[str, Any]:
    fixture = fixture.resolve()
    expected = load_json(expected_path)
    manifest_errors = validate_fixture_manifest(fixture)
    configured_settings = _settings_for_mode(settings or get_settings(), mode)
    scan = Scan(
        id=f"bench_{expected.get('benchmark_id', 'local')}_{mode}",
        mode=ScanMode.repository,
        repository_name=fixture.name,
        repository_workspace_path=str(fixture),
    )
    started_wall = time.perf_counter()
    started_cpu = time.process_time()
    scan = await run_repository_scan(scan, fixture, configured_settings)
    resources = _resource_usage(started_wall, started_cpu)
    comparison = compare_findings(scan, expected)
    ai_review = scan.ai_review.model_dump(mode="json")
    return {
        "schema_version": 1,
        "benchmark_id": expected.get("benchmark_id"),
        "mode": mode,
        "fixture": str(fixture),
        "expected_version": expected.get("version"),
        "status": "failed" if manifest_errors or comparison["false_negatives"] else "passed",
        "manifest_errors": manifest_errors,
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "duration_ms": resources.wall_ms,
            "resource_use": {
                "process_cpu_ms": resources.process_cpu_ms,
                "max_rss_bytes": resources.max_rss_bytes,
            },
            "coverage_percent": scan.coverage_percent,
            "score": scan.score,
            "verdict": scan.verdict,
            "scanner_runs": [run.model_dump(mode="json") for run in scan.scanner_runs],
        },
        "metrics": comparison,
        "qwen_contribution": {
            "mode": mode,
            "status": ai_review.get("status"),
            "provider": ai_review.get("provider"),
            "model": ai_review.get("model"),
            "evidence_provided": ai_review.get("evidence_provided", []),
            "message": ai_review.get("message"),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a NOPE benchmark fixture and compare machine-readable output.")
    parser.add_argument("--fixture", default="benchmarks/fixtures/nope-benchmark-v1")
    parser.add_argument("--expected", default="benchmarks/expected/nope-benchmark-v1.expected.json")
    parser.add_argument("--mode", choices=["scanner-only", "scanner-plus-qwen"], default="scanner-only")
    parser.add_argument("--output", default=".nope-benchmark-results/nope-benchmark.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = asyncio.run(run_benchmark(Path(args.fixture), Path(args.expected), args.mode))
    write_json(Path(args.output), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
