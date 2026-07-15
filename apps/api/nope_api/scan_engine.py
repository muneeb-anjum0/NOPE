from pathlib import Path
from typing import Awaitable, Callable

from nope_api.ai import run_ai_review
from nope_api.attack_surface import build_attack_surface, build_code_graph
from nope_api.config import Settings
from nope_api.models import CoverageRecord, CoverageStatus, Scan, ScanMode, ScannerRun, now_utc
from nope_api.rules_engine import dedupe_findings, run_rules
from nope_api.scanners import scanner_plugins
from nope_api.scoring import calculate_score, coverage_percent, verdict
from nope_api.stack_detector import detect_stack
from nope_api.url_scanner import scan_url


ProgressCallback = Callable[[Scan], Awaitable[None]]
CancellationChecker = Callable[[Scan], Awaitable[bool]]


class ScanCancelled(Exception):
    pass


DOMAINS = [
    "Authentication",
    "Authorization",
    "Secrets",
    "Dependencies",
    "Injection",
    "Supabase",
    "Dynamic testing",
    "URL scanning",
    "Staging",
    "Privacy",
    "CI/CD",
    "Containers",
    "AI abuse",
    "Rate limiting",
]


def default_coverage() -> list[CoverageRecord]:
    return [
        CoverageRecord(domain=domain, status=CoverageStatus.not_tested, notes="No scanner has reported coverage yet.")
        for domain in DOMAINS
    ]


def merge_coverage(existing: list[CoverageRecord], updates: list[CoverageRecord], scanner_runs: list[ScannerRun]) -> list[CoverageRecord]:
    by_domain = {record.domain: record for record in existing}
    for update in updates:
        by_domain[update.domain] = update
    for run in scanner_runs:
        for category in run.coverage_categories:
            current = by_domain.get(category)
            if not current:
                continue
            if run.status == "passed":
                current.status = CoverageStatus.verified if current.status != CoverageStatus.partial else CoverageStatus.partial
                current.scanners = sorted(set(current.scanners + [run.scanner]))
                current.notes = "Scanner completed."
            elif run.status == "failed" and current.status == CoverageStatus.not_tested:
                current.status = CoverageStatus.failed
                current.scanners = sorted(set(current.scanners + [run.scanner]))
                current.notes = run.message
    return list(by_domain.values())


async def _checkpoint(
    scan: Scan,
    progress_callback: ProgressCallback | None,
    cancellation_checker: CancellationChecker | None,
) -> None:
    if progress_callback:
        await progress_callback(scan)
    if cancellation_checker and await cancellation_checker(scan):
        scan.status = "cancelled"
        scan.completed_at = now_utc()
        scan.stages.append({"name": "Scan cancelled", "status": "cancelled", "message": "Cancellation requested."})
        if progress_callback:
            await progress_callback(scan)
        raise ScanCancelled("Scan was cancelled.")


async def run_repository_scan(
    scan: Scan,
    root: Path,
    settings: Settings,
    progress_callback: ProgressCallback | None = None,
    cancellation_checker: CancellationChecker | None = None,
) -> Scan:
    scan.status = "running"
    scan.stages.append({"name": "Detecting stack", "status": "running"})
    await _checkpoint(scan, progress_callback, cancellation_checker)
    scan.stack = detect_stack(root)
    scan.stages[-1]["status"] = "completed"
    await _checkpoint(scan, progress_callback, cancellation_checker)

    scan.stages.append({"name": "Building attack surface", "status": "running"})
    await _checkpoint(scan, progress_callback, cancellation_checker)
    scan.attack_surface = build_attack_surface(root)
    scan.code_graph = build_code_graph(root, scan.attack_surface)
    scan.stages[-1]["status"] = "completed"
    await _checkpoint(scan, progress_callback, cancellation_checker)

    scan.stages.append({"name": "Running NOPE rules", "status": "running"})
    await _checkpoint(scan, progress_callback, cancellation_checker)
    findings = run_rules(root)
    scan.scanner_runs.append(
        ScannerRun(
            scanner="NOPE rules",
            status="passed",
            coverage_categories=["Secrets", "Authorization", "CORS", "Supabase", "AI abuse"],
            findings_count=len(findings),
        )
    )
    scan.stages[-1]["status"] = "completed"
    await _checkpoint(scan, progress_callback, cancellation_checker)

    scan.stages.append({"name": "Running scanner plugins", "status": "running"})
    for plugin in scanner_plugins():
        await _checkpoint(scan, progress_callback, cancellation_checker)
        run, plugin_findings = plugin.execute(root, settings)
        scan.scanner_runs.append(run)
        findings.extend(plugin_findings)
        if run.status == "failed":
            scan.stages[-1]["status"] = "partial"
            scan.status = "partial"
        await _checkpoint(scan, progress_callback, cancellation_checker)
    if scan.stages[-1]["status"] != "partial":
        scan.stages[-1]["status"] = "completed"
    await _checkpoint(scan, progress_callback, cancellation_checker)

    scan.findings = dedupe_findings(findings)
    scan.coverage = merge_coverage(default_coverage(), [], scan.scanner_runs)
    await _checkpoint(scan, progress_callback, cancellation_checker)
    scan.ai_review = await run_ai_review(settings, scan.findings, root=root, scan=scan)
    if scan.ai_review.status in {"Complete", "Partial"}:
        scan.coverage.append(CoverageRecord(domain="Qwen AI review", status=CoverageStatus.partial, scanners=["AI adapter"], notes=scan.ai_review.message))
    elif scan.ai_review.status == "Failed":
        scan.coverage.append(CoverageRecord(domain="Qwen AI review", status=CoverageStatus.failed, scanners=["AI adapter"], notes=scan.ai_review.message))
    else:
        scan.coverage.append(CoverageRecord(domain="Qwen AI review", status=CoverageStatus.not_tested, notes=scan.ai_review.message))
    scan.coverage_percent = coverage_percent(scan.coverage)
    scan.score = calculate_score(scan.findings, scan.coverage)
    scan.verdict = verdict(scan.score, scan.coverage_percent, scan.findings)
    if any(run.status == "failed" for run in scan.scanner_runs):
        scan.status = "partial"
    else:
        scan.status = "completed"
    scan.completed_at = now_utc()
    await _checkpoint(scan, progress_callback, cancellation_checker)
    return scan


async def run_url_only_scan(
    scan: Scan,
    settings: Settings,
    progress_callback: ProgressCallback | None = None,
    cancellation_checker: CancellationChecker | None = None,
) -> Scan:
    scan.status = "running"
    scan.stages.append({"name": "Running non-destructive URL checks", "status": "running"})
    await _checkpoint(scan, progress_callback, cancellation_checker)
    findings, runs, coverage_updates = await scan_url(scan.target_url or "")
    scan.findings = findings
    scan.scanner_runs = runs
    scan.coverage = merge_coverage(default_coverage(), coverage_updates, runs)
    scan.ai_review = await run_ai_review(settings, scan.findings, scan=scan)
    scan.coverage_percent = coverage_percent(scan.coverage)
    scan.score = calculate_score(scan.findings, scan.coverage)
    scan.verdict = verdict(scan.score, scan.coverage_percent, scan.findings)
    scan.stages[-1]["status"] = "completed" if runs and runs[0].status == "passed" else "failed"
    scan.status = "completed" if scan.stages[-1]["status"] == "completed" else "partial"
    scan.completed_at = now_utc()
    await _checkpoint(scan, progress_callback, cancellation_checker)
    return scan


async def run_full_scan(
    scan: Scan,
    root: Path,
    settings: Settings,
    progress_callback: ProgressCallback | None = None,
    cancellation_checker: CancellationChecker | None = None,
) -> Scan:
    await run_repository_scan(scan, root, settings, progress_callback, cancellation_checker)
    if scan.target_url:
        await _checkpoint(scan, progress_callback, cancellation_checker)
        url_findings, url_runs, coverage_updates = await scan_url(scan.target_url)
        scan.findings = dedupe_findings(scan.findings + url_findings)
        scan.scanner_runs.extend(url_runs)
        scan.coverage = merge_coverage(scan.coverage, coverage_updates, url_runs)
        await _checkpoint(scan, progress_callback, cancellation_checker)
    scan.coverage_percent = coverage_percent(scan.coverage)
    scan.score = calculate_score(scan.findings, scan.coverage)
    scan.verdict = verdict(scan.score, scan.coverage_percent, scan.findings)
    scan.mode = ScanMode.full
    scan.completed_at = now_utc()
    await _checkpoint(scan, progress_callback, cancellation_checker)
    return scan
