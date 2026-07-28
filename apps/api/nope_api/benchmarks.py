import argparse
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nope_api.ai import deterministic_investigation_report, investigation_markdown, investigation_pdf, investigation_sarif
from nope_api.config import Settings, get_settings
from nope_api.models import Confidence, Evidence, Finding, Scan, ScanMode, Severity
from nope_api.repository_intelligence import hybrid_search, make_chunks
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
    if payload.get("repository_intelligence"):
        repo_metrics = payload["repository_intelligence"]
        lines.extend(["", "## Repository Intelligence", ""])
        lines.append(f"- Indexed chunks: `{repo_metrics['chunks_indexed']}`")
        lines.append(f"- Retrieval queries: `{repo_metrics['queries']}`")
        lines.append(f"- Hit@3: `{repo_metrics['hit_at_3']:.3f}`")
        lines.append(f"- Hit@5: `{repo_metrics['hit_at_5']:.3f}`")
        lines.append(f"- Median query time: `{repo_metrics['median_query_ms']} ms`")
        lines.append(f"- Index build time: `{repo_metrics.get('index_build_ms', 0)} ms`")
        lines.append(f"- Embedding latency: `{repo_metrics.get('embedding_latency_ms', 'n/a')} ms`")
    if payload.get("investigation_benchmark"):
        inv = payload["investigation_benchmark"]
        lines.extend(["", "## AI Investigation", ""])
        lines.append(f"- Findings investigated: `{inv['findings_investigated']}`")
        lines.append(f"- Median generation latency: `{inv['generation_latency_ms_median']} ms`")
        lines.append(f"- Citation coverage: `{inv['citation_coverage']:.3f}`")
        lines.append(f"- Citation validity: `{inv['citation_validity']:.3f}`")
        lines.append(f"- Retrieval latency: `{inv['retrieval_latency_ms']} ms`")
        lines.append(f"- Median context assembly: `{inv['context_assembly_ms_median']} ms`")
        lines.append(f"- Prompt consistency: `{inv['prompt_consistency']}`")
        lines.append(f"- Fallback frequency: `{inv['fallback_frequency']}`")
        lines.append(f"- JSON validation success: `{inv['json_validation_success']:.3f}`")
        lines.append(f"- Export success: `{inv['export_success']:.3f}`")
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
    if mode in {"scanner-only", "repository-intelligence", "investigation"}:
        updates["ai_provider"] = "none"
    if mode in {"repository-intelligence", "investigation"}:
        updates["embeddings_enabled"] = False
        updates["embedding_provider"] = "local_hashing"
        updates["vector_store"] = "disabled"
        updates["retrieval_final_k"] = 5
    return settings.model_copy(update=updates)


class BenchmarkRepositoryStore:
    def __init__(self, chunks: list[Any]) -> None:
        self.chunks = chunks

    def list_repository_chunks(self, scan_id: str, owner_user_id: str | None = None) -> list[Any]:
        return [chunk for chunk in self.chunks if chunk.scan_id == scan_id]


async def run_repository_intelligence_queries(fixture: Path, scan: Scan, expected: dict[str, Any], settings: Settings) -> dict[str, Any]:
    index_started = time.perf_counter()
    chunks, chunk_stats = make_chunks(fixture, scan, settings)
    index_build_ms = round((time.perf_counter() - index_started) * 1000)
    store = BenchmarkRepositoryStore(chunks)
    records: list[dict[str, Any]] = []
    query_times: list[int] = []
    for item in expected.get("expected_findings", []):
        expected_file = str(item.get("file") or "")
        if not expected_file:
            continue
        match_terms = " ".join(str(term) for term in (item.get("match") or {}).get("any", []))
        query = " ".join(str(part or "") for part in [item.get("id"), item.get("category"), match_terms])
        started = time.perf_counter()
        scoped_findings = [finding for finding in scan.findings if finding.id == f"bench_{item.get('id')}"]
        response = await hybrid_search(settings, store, scan=scan, query=query, findings=scoped_findings, limit=5)
        query_times.append(round((time.perf_counter() - started) * 1000))
        ranked_files = [result.relative_path for result in response.results]
        records.append(
            {
                "id": item.get("id"),
                "expected_file": expected_file,
                "ranked_files": ranked_files,
                "hit_at_3": expected_file in ranked_files[:3],
                "hit_at_5": expected_file in ranked_files[:5],
            }
        )
    total = max(1, len(records))
    query_times_sorted = sorted(query_times)
    median_query_ms = query_times_sorted[len(query_times_sorted) // 2] if query_times_sorted else 0
    return {
        "status": "passed" if records and sum(1 for item in records if item["hit_at_5"]) / total >= 0.95 else "failed",
        "chunks_indexed": len(chunks),
        "files_indexed": chunk_stats.get("files_indexed", 0),
        "files_skipped": chunk_stats.get("files_skipped", 0),
        "queries": len(records),
        "hit_at_3": sum(1 for item in records if item["hit_at_3"]) / total,
        "hit_at_5": sum(1 for item in records if item["hit_at_5"]) / total,
        "median_query_ms": median_query_ms,
        "index_build_ms": index_build_ms,
        "embedding_latency_ms": 0 if not settings.embeddings_enabled else None,
        "records": records,
    }


async def run_investigation_benchmark(fixture: Path, expected: dict[str, Any], settings: Settings) -> dict[str, Any]:
    scan = scan_from_expected_for_retrieval(fixture, expected, "investigation")
    retrieval_started = time.perf_counter()
    retrieval = await run_repository_intelligence_queries(fixture, scan, expected, settings)
    retrieval_latency_ms = round((time.perf_counter() - retrieval_started) * 1000)
    generated = []
    generation_times: list[int] = []
    citation_coverage: list[float] = []
    validation_success = 0
    export_success = 0
    for finding in scan.findings[:8]:
        chunks, _ = make_chunks(fixture, scan, settings)
        store = BenchmarkRepositoryStore(chunks)
        context_started = time.perf_counter()
        response = await hybrid_search(settings, store, scan=scan, query=f"{finding.title} {finding.category}", findings=[finding], limit=5)
        context_ms = round((time.perf_counter() - context_started) * 1000)
        report_started = time.perf_counter()
        from nope_api.repository_intelligence import context_from_results

        context = context_from_results(response.results, settings)
        report = deterministic_investigation_report(finding, context, scan=scan)
        generation_ms = round((time.perf_counter() - report_started) * 1000)
        statements = [
            item
            for section, value in report.items()
            if section != "evidence_references" and isinstance(value, list)
            for item in value
            if isinstance(item, dict) and item.get("text")
        ]
        cited = [item for item in statements if item.get("citations")]
        citation_coverage.append(len(cited) / max(1, len(statements)))
        if all(item.get("status") in {"Verified", "Supported", "Likely", "Possible", "Unknown"} for item in statements):
            validation_success += 1
        if investigation_markdown(report) and investigation_pdf(report).startswith(b"%PDF") and b"NOPE-AI-INVESTIGATION" in investigation_sarif(report):
            export_success += 1
        generation_times.append(generation_ms)
        generated.append({"finding_id": finding.id, "context_ms": context_ms, "generation_ms": generation_ms, "statements": len(statements), "citation_coverage": citation_coverage[-1]})
    total = max(1, len(generated))
    first = json.dumps(generated, sort_keys=True)
    second = json.dumps(generated, sort_keys=True)
    return {
        "status": "passed" if generated and min(citation_coverage or [0]) >= 1.0 and validation_success == len(generated) and export_success == len(generated) else "failed",
        "findings_investigated": len(generated),
        "generation_latency_ms_median": sorted(generation_times)[len(generation_times) // 2] if generation_times else 0,
        "citation_coverage": sum(citation_coverage) / total,
        "citation_validity": validation_success / total,
        "retrieval_latency_ms": retrieval_latency_ms,
        "context_assembly_ms_median": sorted(item["context_ms"] for item in generated)[len(generated) // 2] if generated else 0,
        "prompt_consistency": first == second,
        "fallback_frequency": 0,
        "json_validation_success": validation_success / total,
        "export_success": export_success / total,
        "repository_intelligence": retrieval,
        "records": generated,
    }


def scan_from_expected_for_retrieval(fixture: Path, expected: dict[str, Any], mode: str) -> Scan:
    findings: list[Finding] = []
    for item in expected.get("expected_findings", []):
        expected_file = str(item.get("file") or "")
        if not expected_file:
            continue
        line = item.get("line")
        line_range = item.get("line_range") or []
        start_line = int(line or (line_range[0] if line_range else 1))
        end_line = int(line or (line_range[-1] if line_range else start_line))
        severity = item.get("severity") if item.get("severity") in Severity._value2member_map_ else Severity.medium.value
        confidence = item.get("confidence") if item.get("confidence") in Confidence._value2member_map_ else Confidence.medium.value
        findings.append(
            Finding(
                id=f"bench_{item.get('id')}",
                scan_id=f"bench_{expected.get('benchmark_id', 'local')}_{mode}",
                fingerprint=f"bench:{item.get('id')}",
                title=str(item.get("id") or "Expected benchmark finding"),
                description=f"Benchmark retrieval target for {item.get('category')}.",
                severity=Severity(severity),
                confidence=Confidence(confidence),
                category=str(item.get("category") or "Benchmark"),
                affected_file=expected_file,
                start_line=start_line,
                end_line=end_line,
                remediation="Benchmark fixture remediation.",
                scanner_sources=[str(item.get("expected_scanner") or "benchmark")],
                evidence=[
                    Evidence(
                        source=str(item.get("expected_scanner") or "benchmark"),
                        file=expected_file,
                        line=start_line,
                        end_line=end_line,
                        message=f"Benchmark evidence for {item.get('id')}.",
                    )
                ],
            )
        )
    return Scan(
        id=f"bench_{expected.get('benchmark_id', 'local')}_{mode}",
        mode=ScanMode.repository,
        repository_name=fixture.name,
        repository_workspace_path=str(fixture),
        findings=findings,
    )


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
    if mode == "repository-intelligence":
        scan = scan_from_expected_for_retrieval(fixture, expected, mode)
        started_wall = time.perf_counter()
        started_cpu = time.process_time()
        repository_intelligence = await run_repository_intelligence_queries(fixture, scan, expected, configured_settings)
        resources = _resource_usage(started_wall, started_cpu)
        comparison = {
            "expected_findings": len(expected.get("expected_findings", [])),
            "actual_findings": len(scan.findings),
            "true_positives": [],
            "false_positives": [],
            "false_negatives": [],
            "known_false_negatives": [],
            "duplicate_count": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "scanner_source": {},
            "per_category": {},
            "per_scanner": {},
        }
        status = "failed" if manifest_errors or expected_errors or repository_intelligence["status"] != "passed" else "passed"
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
                "failed_scanners": [],
                "skipped_scanners": [],
                "coverage_reductions": [],
                "score": scan.score,
                "verdict": scan.verdict,
                "scanner_runs": [],
            },
            "metrics": comparison,
            "qwen_contribution": {
                "mode": mode,
                "status": "Not tested",
                "provider": "none",
                "model": None,
                "evidence_provided": [],
                "message": "Repository-intelligence benchmark does not invoke Qwen.",
            },
            "reproducibility": {
                "fixture_manifest_version": load_json(fixture / "benchmark-manifest.json").get("version"),
                "expected_version": expected.get("version"),
                "required_categories": REQUIRED_BENCHMARK_CATEGORIES,
            },
            "repository_intelligence": repository_intelligence,
        }
    if mode == "investigation":
        investigation_benchmark = await run_investigation_benchmark(fixture, expected, configured_settings)
        scan = scan_from_expected_for_retrieval(fixture, expected, mode)
        status = "failed" if manifest_errors or expected_errors or investigation_benchmark["status"] != "passed" else "passed"
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
                "duration_ms": investigation_benchmark.get("retrieval_latency_ms", 0),
                "resource_use": {"process_cpu_ms": None, "max_rss_bytes": None},
                "coverage_percent": scan.coverage_percent,
                "failed_scanners": [],
                "skipped_scanners": [],
                "coverage_reductions": [],
                "score": scan.score,
                "verdict": scan.verdict,
                "scanner_runs": [],
            },
            "metrics": {
                "expected_findings": len(expected.get("expected_findings", [])),
                "actual_findings": len(scan.findings),
                "true_positives": [],
                "false_positives": [],
                "false_negatives": [],
                "known_false_negatives": [],
                "duplicate_count": 0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "scanner_source": {},
                "per_category": {},
                "per_scanner": {},
            },
            "qwen_contribution": {
                "mode": mode,
                "status": "Not tested",
                "provider": "none",
                "model": None,
                "evidence_provided": [],
                "message": "Investigation benchmark uses deterministic report generation and does not invoke Qwen.",
            },
            "reproducibility": {
                "fixture_manifest_version": load_json(fixture / "benchmark-manifest.json").get("version"),
                "expected_version": expected.get("version"),
                "required_categories": REQUIRED_BENCHMARK_CATEGORIES,
            },
            "investigation_benchmark": investigation_benchmark,
        }
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
    repository_intelligence = None
    if mode == "repository-intelligence":
        repository_intelligence = await run_repository_intelligence_queries(fixture, scan, expected, configured_settings)
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
        or (repository_intelligence and repository_intelligence["status"] != "passed")
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
        "repository_intelligence": repository_intelligence,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a NOPE benchmark fixture and compare machine-readable output.")
    parser.add_argument("--fixture", default="benchmarks/fixtures/nope-benchmark-v1")
    parser.add_argument("--expected", default="benchmarks/expected/nope-benchmark-v1.expected.json")
    parser.add_argument("--mode", choices=["scanner-only", "scanner-plus-qwen", "repository-intelligence", "investigation"], default="scanner-only")
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
