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
    "backend-hardcoded-secret",
    "frontend-exposed-secret",
    "env-exposure",
    "public-source-map",
    "sql-injection",
    "nosql-injection",
    "command-injection",
    "stored-xss",
    "reflected-xss",
    "unsafe-html",
    "ssrf",
    "path-traversal",
    "unsafe-archive-extraction",
    "file-upload",
    "idor",
    "missing-ownership-check",
    "missing-tenant-scope",
    "frontend-only-authorization",
    "authentication-bypass",
    "weak-password-reset",
    "login-brute-force",
    "signup-abuse",
    "otp-flooding",
    "insecure-cors",
    "missing-csrf-protection",
    "missing-api-rate-limit",
    "ai-cost-abuse",
    "vulnerable-dependency",
    "unsafe-dockerfile",
    "unsafe-iac",
    "debug-endpoint",
    "staging-exposure",
    "supabase-missing-rls",
    "supabase-overly-permissive-rls",
    "public-supabase-storage-bucket",
    "firebase-permissive-rules",
    "tracker-before-consent",
    "missing-security-headers",
    "unsafe-cookie-configuration",
    "shell-command-injection-build-script",
    "credential-leakage-logs",
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


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    metrics = payload["metrics"]
    lines = [
        f"# NOPE Benchmark: {payload['benchmark_id']} ({payload['mode']})",
        "",
        f"- Status: **{payload['status']}**",
        f"- Expected fixtures: `{metrics['expected_findings']}`",
        f"- Actual findings: `{metrics['actual_findings']}`",
        f"- True positives: `{len(metrics['true_positives'])}`",
        f"- False positives: `{len(metrics['false_positives'])}`",
        f"- False negatives: `{len(metrics['false_negatives'])}`",
        f"- Related duplicate/supporting findings: `{metrics['duplicate_count']}`",
        f"- Precision: `{metrics['precision']:.3f}`",
        f"- Recall: `{metrics['recall']:.3f}`",
        f"- F1: `{metrics['f1']:.3f}`",
        f"- Duration: `{payload['scan']['duration_ms']} ms`",
        f"- Coverage: `{payload['scan']['coverage_percent']}%`",
        f"- Qwen status: `{payload['qwen_contribution']['status']}`",
        "",
        "## False Negatives",
        "",
    ]
    if metrics["false_negatives"]:
        lines.extend(f"- `{item['id']}` in `{item.get('file')}`" for item in metrics["false_negatives"])
    else:
        lines.append("- None")
    lines.extend(["", "## False Positives", ""])
    if metrics["false_positives"]:
        lines.extend(
            f"- `{item['title']}` in `{item.get('file')}` from `{item.get('scanner')}`"
            for item in metrics["false_positives"]
        )
    else:
        lines.append("- None")
    lines.extend(["", "## Per Scanner", ""])
    lines.extend(f"- `{scanner}`: `{count}`" for scanner, count in sorted(metrics["scanner_source"].items()))
    lines.extend(["", "## Per-Category Metrics", ""])
    for category, bucket in sorted(metrics.get("per_category", {}).items()):
        lines.append(
            f"- `{category}`: precision `{bucket['precision']:.3f}`, recall `{bucket['recall']:.3f}`, "
            f"F1 `{bucket['f1']:.3f}`"
        )
    lines.extend(["", "## Per-Expected-Scanner Metrics", ""])
    for scanner, bucket in sorted(metrics.get("per_scanner", {}).items()):
        lines.append(
            f"- `{scanner}`: precision `{bucket['precision']:.3f}`, recall `{bucket['recall']:.3f}`, "
            f"F1 `{bucket['f1']:.3f}`"
        )
    lines.extend(["", "## Scanner Health Summary", ""])
    failed = payload["scan"].get("failed_scanners", [])
    skipped = payload["scan"].get("skipped_scanners", [])
    lines.append(f"- Failed scanners: `{len(failed)}`")
    lines.append(f"- Skipped scanners: `{len(skipped)}`")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    for item in manifest.get("negative_controls", []):
        rel = item.get("file")
        if rel and not (fixture / str(rel)).exists():
            problems.append(f"Negative-control file is missing for {item.get('id')}: {rel}")
    return problems


def validate_expected_manifest(expected: dict[str, Any]) -> list[str]:
    required = {
        "id",
        "category",
        "file",
        "severity",
        "confidence",
        "cwe",
        "owasp",
        "expected_scanner",
        "qwen_enrichment_expected",
        "dedupe_expected",
        "match",
    }
    problems: list[str] = []
    expected_ids = set()
    for item in expected.get("expected_findings", []):
        expected_ids.add(str(item.get("id")))
        missing = sorted(required - set(item))
        if missing:
            problems.append(f"Expected finding {item.get('id')} is missing fields: {', '.join(missing)}")
        if not (item.get("line") or item.get("line_range")):
            problems.append(f"Expected finding {item.get('id')} must define line or line_range.")
    missing_categories = [category for category in REQUIRED_BENCHMARK_CATEGORIES if category not in expected_ids]
    problems.extend(f"Missing expected finding: {category}" for category in missing_categories)
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


def _related_to_matched_expected(finding: Finding, matched_expected: list[dict[str, Any]]) -> bool:
    file = str(finding.affected_file or "").lower()
    category = finding.category.lower()
    for expected in matched_expected:
        expected_file = str(expected.get("file") or "").lower()
        expected_category = str(expected.get("category") or "").lower()
        if expected_file and expected_file in file:
            return True
        if expected_category and expected_category == category and expected.get("dedupe_expected"):
            return True
    return False


def _score(tp: int, fp: int, fn: int, expected_count: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / expected_count if expected_count else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _bucket_metrics(expected_items: list[dict[str, Any]], matched_ids: set[str], false_positive_payloads: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_category: dict[str, dict[str, Any]] = {}
    for item in expected_items:
        category = str(item.get("category") or "unknown")
        bucket = by_category.setdefault(category, {"expected": 0, "true_positives": 0, "false_negatives": 0, "false_positives": 0})
        bucket["expected"] += 1
        if str(item.get("id")) in matched_ids:
            bucket["true_positives"] += 1
        else:
            bucket["false_negatives"] += 1
    for finding in false_positive_payloads:
        category = str(finding.get("category") or "unknown")
        bucket = by_category.setdefault(category, {"expected": 0, "true_positives": 0, "false_negatives": 0, "false_positives": 0})
        bucket["false_positives"] += 1
    for bucket in by_category.values():
        scores = _score(bucket["true_positives"], bucket["false_positives"], bucket["false_negatives"], bucket["expected"])
        bucket.update(scores)
    return by_category


def _scanner_metrics(expected_items: list[dict[str, Any]], matched_ids: set[str], false_positive_payloads: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_scanner: dict[str, dict[str, Any]] = {}
    for item in expected_items:
        scanner = str(item.get("expected_scanner") or "unknown")
        bucket = by_scanner.setdefault(scanner, {"expected": 0, "true_positives": 0, "false_negatives": 0, "false_positives": 0})
        bucket["expected"] += 1
        if str(item.get("id")) in matched_ids:
            bucket["true_positives"] += 1
        else:
            bucket["false_negatives"] += 1
    for finding in false_positive_payloads:
        scanner = str(finding.get("scanner") or "unknown")
        bucket = by_scanner.setdefault(scanner, {"expected": 0, "true_positives": 0, "false_negatives": 0, "false_positives": 0})
        bucket["false_positives"] += 1
    for bucket in by_scanner.values():
        scores = _score(bucket["true_positives"], bucket["false_positives"], bucket["false_negatives"], bucket["expected"])
        bucket.update(scores)
    return by_scanner


def compare_findings(scan: Scan, expected: dict[str, Any]) -> dict[str, Any]:
    findings = scan.findings
    matched_fingerprints: set[str] = set()
    true_positives: list[dict[str, Any]] = []
    known_false_negatives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []
    matched_expected: list[dict[str, Any]] = []
    for item in expected.get("expected_findings", []):
        allow_shared_finding = bool(item.get("dedupe_expected"))
        match = next(
            (
                finding
                for finding in findings
                if (allow_shared_finding or finding.fingerprint not in matched_fingerprints)
                and _matches_expected(finding, item)
            ),
            None,
        )
        if match:
            matched_fingerprints.add(match.fingerprint)
            true_positives.append({"expected_id": item["id"], "finding": finding_payload(match)})
            matched_expected.append(item)
        elif item.get("known_false_negative"):
            known_false_negatives.append(item)
        else:
            false_negatives.append(item)
    related_duplicates = [
        finding
        for finding in findings
        if finding.fingerprint not in matched_fingerprints and _related_to_matched_expected(finding, matched_expected)
    ]
    duplicate_fingerprints = {finding.fingerprint for finding in related_duplicates}
    false_positives = [
        finding_payload(finding)
        for finding in findings
        if finding.fingerprint not in matched_fingerprints and finding.fingerprint not in duplicate_fingerprints
    ]
    by_scanner: dict[str, int] = {}
    for finding in findings:
        for source in finding.scanner_sources or [finding.scanner or "unknown"]:
            by_scanner[source] = by_scanner.get(source, 0) + 1
    matched_ids = {item["expected_id"] for item in true_positives}
    scores = _score(
        len(true_positives),
        len(false_positives),
        len(false_negatives) + len(known_false_negatives),
        len(expected.get("expected_findings", [])),
    )
    return {
        "expected_findings": len(expected.get("expected_findings", [])),
        "actual_findings": len(findings),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "known_false_negatives": known_false_negatives,
        "false_negatives": false_negatives,
        "duplicate_count": len(related_duplicates),
        "duplicates": [finding_payload(finding) for finding in related_duplicates],
        "precision": scores["precision"],
        "recall": scores["recall"],
        "f1": scores["f1"],
        "per_category": _bucket_metrics(expected.get("expected_findings", []), matched_ids, false_positives),
        "per_scanner": _scanner_metrics(expected.get("expected_findings", []), matched_ids, false_positives),
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
    expected_errors = validate_expected_manifest(expected)
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
    failed_scanners = [run.model_dump(mode="json") for run in scan.scanner_runs if run.status == "failed"]
    skipped_scanners = [run.model_dump(mode="json") for run in scan.scanner_runs if run.status == "skipped"]
    coverage_reductions = []
    for record in scan.coverage:
        status_value = getattr(record.status, "value", record.status)
        if str(status_value) in {"failed", "not_tested", "not_applicable"}:
            coverage_reductions.append(record.model_dump(mode="json"))
    status = "passed"
    if (
        manifest_errors
        or expected_errors
        or failed_scanners
        or comparison["false_negatives"]
        or comparison["known_false_negatives"]
        or comparison["precision"] < 0.90
        or comparison["recall"] < 0.95
        or comparison["f1"] < 0.925
    ):
        status = "failed"
    return {
        "schema_version": 1,
        "benchmark_id": expected.get("benchmark_id"),
        "mode": mode,
        "fixture": str(fixture),
        "expected_version": expected.get("version"),
        "status": status,
        "manifest_errors": manifest_errors,
        "expected_errors": expected_errors,
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "duration_ms": resources.wall_ms,
            "resource_use": {
                "process_cpu_ms": resources.process_cpu_ms,
                "max_rss_bytes": resources.max_rss_bytes,
            },
            "coverage_percent": scan.coverage_percent,
            "failed_scanners": failed_scanners,
            "skipped_scanners": skipped_scanners,
            "coverage_reductions": coverage_reductions,
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
        "reproducibility": {
            "fixture_manifest_version": load_json(fixture / "benchmark-manifest.json").get("version"),
            "expected_version": expected.get("version"),
            "required_categories": REQUIRED_BENCHMARK_CATEGORIES,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a NOPE benchmark fixture and compare machine-readable output.")
    parser.add_argument("--fixture", default="benchmarks/fixtures/nope-benchmark-v1")
    parser.add_argument("--expected", default="benchmarks/expected/nope-benchmark-v1.expected.json")
    parser.add_argument("--mode", choices=["scanner-only", "scanner-plus-qwen"], default="scanner-only")
    parser.add_argument("--output", default=".nope-benchmark-results/nope-benchmark.json")
    parser.add_argument("--markdown-output", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = asyncio.run(run_benchmark(Path(args.fixture), Path(args.expected), args.mode))
    output = Path(args.output)
    write_json(output, result)
    markdown_output = Path(args.markdown_output) if args.markdown_output else output.with_suffix(".md")
    write_markdown(markdown_output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
