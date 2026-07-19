from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
import json
from textwrap import wrap
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from nope_api.drift import BaselineSnapshot, compare_scans
from nope_api.models import CoverageStatus, Scan
from nope_api.rag import redact_text


@dataclass
class ReportContext:
    drift_events: list[dict[str, Any]] = field(default_factory=list)
    baselines: list[dict[str, Any]] = field(default_factory=list)
    baseline_comparison: dict[str, Any] | None = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _redact(value: Any) -> str:
    if value is None:
        return "Not provided"
    return redact_text(str(value))


def _count_findings(scan: Scan) -> Counter:
    return Counter(finding.severity.value for finding in scan.findings)


def _scanner_rows(scan: Scan) -> list[list[str]]:
    if not scan.scanner_runs:
        return [["No scanner runs recorded.", "", "", ""]]
    return [
        [
            _redact(run.scanner),
            _redact(run.version),
            _redact(run.status),
            _redact(run.message or f"{run.findings_count} findings"),
        ]
        for run in scan.scanner_runs
    ]


def _coverage_rows(scan: Scan) -> list[list[str]]:
    if not scan.coverage:
        return [["No coverage records were produced.", "", ""]]
    return [[_redact(record.domain), _redact(record.status.value), _redact(record.notes)] for record in scan.coverage]


def _untested_areas(scan: Scan) -> list[str]:
    return [
        f"{record.domain}: {record.status.value} - {record.notes}"
        for record in scan.coverage
        if record.status in {CoverageStatus.not_tested, CoverageStatus.failed, CoverageStatus.partial}
    ]


def _suppressed_count(scan: Scan) -> int:
    return sum(1 for finding in scan.findings if finding.status == "suppressed" or finding.suppression is not None)


def _lifecycle_summary(scan: Scan) -> dict[str, Any]:
    states = Counter(finding.status for finding in scan.findings)
    return {
        "states": dict(states),
        "reintroduced": sum(1 for finding in scan.findings if finding.status == "reintroduced" or finding.baseline_state.value == "reintroduced"),
        "recurring": sum(1 for finding in scan.findings if finding.recurrence_count > 1),
        "suppressed": _suppressed_count(scan),
        "schema_versions": sorted({finding.schema_version for finding in scan.findings}),
    }


def _failed_scanners(scan: Scan) -> list[str]:
    return [f"{run.scanner}: {run.message or 'failed'}" for run in scan.scanner_runs if run.status == "failed"]


def _dynamic_summary(scan: Scan) -> dict[str, Any]:
    runs = [run for run in scan.scanner_runs if run.scanner in {"OWASP ZAP", "NOPE URL scanner", "NOPE sandbox"}]
    coverage = [record for record in scan.coverage if record.domain in {"Dynamic testing", "URL scanning"}]
    findings = [finding for finding in scan.findings if "Dynamic" in finding.category or finding.scanner in {"OWASP ZAP", "NOPE URL scanner"}]
    return {
        "scanner_runs": [
            {
                "scanner": _redact(run.scanner),
                "version": _redact(run.version),
                "status": _redact(run.status),
                "message": _redact(run.message),
                "findings_count": run.findings_count,
                "raw_artifact_id": run.raw_artifact_id,
            }
            for run in runs
        ],
        "coverage": [
            {"domain": _redact(record.domain), "status": _redact(record.status.value), "notes": _redact(record.notes)}
            for record in coverage
        ],
        "findings_count": len(findings),
    }


def _rules_v2_summary(scan: Scan) -> dict[str, Any]:
    payload = scan.rules_v2 or {}
    coverage = payload.get("coverage") or {}
    decisions = payload.get("decisions") or []
    withheld = [item for item in decisions if item.get("result") == "withheld"]
    needs_review = [item for item in decisions if item.get("result") == "needs_manual_review"]
    rejected = [item for item in decisions if item.get("result") == "rejected"]
    return {
        "version": payload.get("version"),
        "catalog": payload.get("catalog") or {},
        "coverage": coverage,
        "metrics": payload.get("metrics") or {},
        "failures": payload.get("failures") or [],
        "withheld_candidates": len(withheld),
        "needs_manual_review": len(needs_review),
        "rejected_candidates": len(rejected),
        "withheld_sample": withheld[:10],
    }


def _privacy_warnings(scan: Scan) -> list[str]:
    warnings: list[str] = []
    if any("tracker" in finding.title.lower() or "privacy" in finding.category.lower() for finding in scan.findings):
        warnings.append("Privacy-sensitive findings are present in the tested scope.")
    if any(item.sensitive_output for item in scan.attack_surface):
        warnings.append("One or more routes may return sensitive data.")
    return warnings or ["No explicit privacy warning was produced by the available evidence."]


def _staging_warnings(scan: Scan) -> list[str]:
    haystack = " ".join([scan.target_url or "", scan.repository_name or "", *(finding.title for finding in scan.findings)]).lower()
    if any(term in haystack for term in ["staging", "debug", "preview", "dev."]):
        return ["Staging, debug, preview, or development exposure indicators were observed."]
    return ["No staging exposure warning was produced by the available evidence."]


def _baseline_summary(scan: Scan, context: ReportContext) -> dict[str, Any]:
    if context.baseline_comparison:
        return context.baseline_comparison
    if context.baselines:
        latest = context.baselines[0]
        try:
            comparison = compare_scans(scan, BaselineSnapshot(**latest["data"]), baseline_id=latest["id"])
            return comparison.model_dump(mode="json")
        except Exception:
            comparison = None
    if context.drift_events:
        return {
            "summary": {"total_drift_events": len(context.drift_events)},
            "drift_events": context.drift_events,
        }
    return {"summary": {"total_drift_events": 0}, "drift_events": []}


def report_json(scan: Scan, context: ReportContext | None = None) -> dict:
    context = context or ReportContext()
    counts = _count_findings(scan)
    baseline = _baseline_summary(scan, context)
    return {
        "brand": "NOPE",
        "generated_at": context.generated_at.isoformat(),
        "scan": scan.model_dump(mode="json"),
        "summary": {
            "verdict": scan.verdict,
            "score": scan.score,
            "coverage_percent": scan.coverage_percent,
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "suppressed": _suppressed_count(scan),
            "failed_scanners": len(_failed_scanners(scan)),
        },
        "dynamic_testing": _dynamic_summary(scan),
        "rules_v2": _rules_v2_summary(scan),
        "finding_lifecycle": _lifecycle_summary(scan),
        "baseline_comparison": baseline,
        "limitations": _limitations(scan),
        "methodology": _methodology(),
    }


def report_markdown(scan: Scan, context: ReportContext | None = None) -> str:
    context = context or ReportContext()
    counts = _count_findings(scan)
    baseline = _baseline_summary(scan, context)
    lines = [
        f"# NOPE Report: {scan.id}",
        "",
        "NOPE uses deterministic scanner evidence first and focused AI assistance only where available.",
        "",
        "## Executive Summary",
        f"- Verdict: {_redact(scan.verdict)}",
        f"- Score: {scan.score}",
        f"- Coverage: {scan.coverage_percent}%",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        f"- Suppressed: {_suppressed_count(scan)}",
        "",
        "## Scope",
        f"- Project: {_redact(scan.project_id)}",
        f"- Mode: {scan.mode.value}",
        f"- Repository: {_redact(scan.repository_name)}",
        f"- Commit: {_redact(scan.commit_sha)}",
        f"- Target URL: {_redact(scan.target_url)}",
        f"- Date: {context.generated_at.isoformat()}",
        "",
        "## Scanner Status",
    ]
    for row in _scanner_rows(scan):
        lines.append(f"- {row[0]} {row[1]}: {row[2]} - {row[3]}")
    lines.extend(["", "## Coverage"])
    for row in _coverage_rows(scan):
        lines.append(f"- {row[0]}: {row[1]} - {row[2]}")
    lines.extend(["", "## Dynamic Testing"])
    dynamic = _dynamic_summary(scan)
    if not dynamic["scanner_runs"]:
        lines.append("- No dynamic scanner run was recorded.")
    for run in dynamic["scanner_runs"]:
        artifact = f"; artifact: {run['raw_artifact_id']}" if run.get("raw_artifact_id") else ""
        lines.append(f"- {run['scanner']} {run['version']}: {run['status']} - {run['message']}{artifact}")
    for record in dynamic["coverage"]:
        lines.append(f"- Coverage {record['domain']}: {record['status']} - {record['notes']}")
    rules_v2 = _rules_v2_summary(scan)
    lines.extend(["", "## Rules v2"])
    if rules_v2["version"]:
        coverage = rules_v2["coverage"]
        lines.append(f"- Version: {rules_v2['version']}")
        lines.append(f"- Registered rules: {rules_v2['catalog'].get('rule_count', 0)}")
        lines.append(f"- Candidates: {coverage.get('candidate_count', 0)}")
        lines.append(f"- Promoted: {coverage.get('promoted', 0)}")
        lines.append(f"- Withheld: {coverage.get('withheld', 0)}")
        lines.append(f"- Needs manual review: {coverage.get('needs_manual_review', 0)}")
        lines.append(f"- Rejected: {coverage.get('rejected', 0)}")
        for item in rules_v2["withheld_sample"]:
            lines.append(f"- Withheld {item.get('rule_id')}: {_redact(item.get('reason'))}")
    else:
        lines.append("- Rules v2 did not run for this scan.")
    lines.extend(["", "## Findings"])
    if not scan.findings:
        lines.append("No findings were produced in the tested scope.")
    for finding in scan.findings:
        lines.extend(
            [
                f"### {finding.severity.value.upper()}: {_redact(finding.title)}",
                f"- Category: {_redact(finding.category)}",
                f"- Confidence: {finding.confidence.value}",
                f"- File: {_redact(finding.affected_file)}",
                f"- Route: {_redact(finding.affected_route)}",
                f"- Status: {_redact(finding.status)}",
                f"- Fingerprint: {_redact(finding.fingerprint)}",
                f"- Original scanner fingerprint: {_redact(finding.original_fingerprint)}",
                f"- Recurrence count: {finding.recurrence_count}",
                f"- Remediation: {_redact(finding.remediation)}",
                "",
            ]
        )
    lifecycle = _lifecycle_summary(scan)
    lines.extend(["## Finding Lifecycle", *[f"- {key}: {value}" for key, value in lifecycle["states"].items()]])
    lines.extend(["", "## Baseline Comparison", f"- Drift events: {baseline.get('summary', {}).get('total_drift_events', 0)}"])
    lines.extend(["", "## Untested Areas"])
    for item in _untested_areas(scan) or ["No explicit untested areas were recorded."]:
        lines.append(f"- {_redact(item)}")
    lines.extend(["", "## Limitations"])
    for item in _limitations(scan):
        lines.append(f"- {item}")
    lines.extend(["", "## Methodology"])
    for item in _methodology():
        lines.append(f"- {item}")
    return "\n".join(lines)


def report_sarif(scan: Scan, context: ReportContext | None = None) -> dict:
    rules = {}
    results = []
    for finding in scan.findings:
        rule_id = finding.cwe or finding.original_rule_id or finding.category
        rules[rule_id] = {
            "id": rule_id,
            "name": _redact(finding.title),
            "shortDescription": {"text": _redact(finding.title)},
            "fullDescription": {"text": _redact(finding.description)},
            "help": {"text": _redact(finding.remediation)},
        }
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": _redact(finding.affected_file or "target-url")},
                "region": {"startLine": finding.start_line or finding.evidence[0].line or 1 if finding.evidence else 1},
            }
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.severity.value in {"critical", "high"} else "warning",
                "message": {"text": _redact(finding.title)},
                "locations": [location],
                "partialFingerprints": {
                    "nopeCanonicalFingerprint": finding.fingerprint,
                    "scannerFingerprint": finding.original_fingerprint or finding.fingerprint,
                },
                "properties": {
                    "status": finding.status,
                    "recurrence_count": finding.recurrence_count,
                    "scanner_sources": finding.scanner_sources,
                    "schema_version": finding.schema_version,
                    "rules_v2": finding.source_metadata.get("rules_v2", False),
                    "rule_version": finding.source_metadata.get("rule_version"),
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "NOPE", "rules": list(rules.values())}},
                "results": results,
                "properties": {"scan_id": scan.id, "verdict": scan.verdict, "rules_v2": _rules_v2_summary(scan)},
            }
        ],
    }


def report_pdf(scan: Scan, context: ReportContext | None = None) -> bytes:
    context = context or ReportContext()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=f"NOPE Security Report {scan.id}",
        author="NOPE",
        rightMargin=42,
        leftMargin=42,
        topMargin=48,
        bottomMargin=48,
        pageCompression=0,
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []
    counts = _count_findings(scan)
    baseline = _baseline_summary(scan, context)

    def heading(text: str, level: int = 1) -> None:
        story.append(Paragraph(_redact(text), styles["Heading1" if level == 1 else "Heading2"]))
        story.append(Spacer(1, 8))

    def para(text: str) -> None:
        story.append(Paragraph(_redact(text), styles["BodyText"]))
        story.append(Spacer(1, 6))

    heading("NOPE Security Report")
    para("Evidence over vibes. This report summarizes the tested scope and does not claim an application is fully secure.")
    _table(
        story,
        [
            ["Project", _redact(scan.project_id)],
            ["Repository", _redact(scan.repository_name)],
            ["Commit", _redact(scan.commit_sha)],
            ["Target", _redact(scan.target_url)],
            ["Date", context.generated_at.isoformat()],
            ["Scope", scan.mode.value],
        ],
    )

    heading("Executive Summary", 2)
    _table(
        story,
        [
            ["Verdict", _redact(scan.verdict)],
            ["Score", str(scan.score)],
            ["Coverage", f"{scan.coverage_percent}%"],
            ["Critical / High / Medium / Low", f"{counts['critical']} / {counts['high']} / {counts['medium']} / {counts['low']}"],
            ["Suppressed findings", str(_suppressed_count(scan))],
            ["Failed scanners", str(len(_failed_scanners(scan)))],
        ],
    )

    heading("Coverage", 2)
    _table(story, [["Domain", "Status", "Notes"], *_coverage_rows(scan)], header=True)
    heading("Dynamic Testing", 2)
    dynamic = _dynamic_summary(scan)
    if dynamic["scanner_runs"]:
        _table(
            story,
            [["Scanner", "Version", "Status", "Message"], *[
                [run["scanner"], run["version"], run["status"], run["message"]]
                for run in dynamic["scanner_runs"]
            ]],
            header=True,
        )
    else:
        para("No dynamic scanner run was recorded.")
    heading("Scanner Status", 2)
    _table(story, [["Scanner", "Version", "Status", "Message"], *_scanner_rows(scan)], header=True)
    heading("Rules v2", 2)
    rules_v2 = _rules_v2_summary(scan)
    if rules_v2["version"]:
        coverage = rules_v2["coverage"]
        _table(
            story,
            [
                ["Version", str(rules_v2["version"])],
                ["Registered rules", str(rules_v2["catalog"].get("rule_count", 0))],
                ["Candidates", str(coverage.get("candidate_count", 0))],
                ["Promoted", str(coverage.get("promoted", 0))],
                ["Withheld", str(coverage.get("withheld", 0))],
                ["Needs review", str(coverage.get("needs_manual_review", 0))],
                ["Rejected", str(coverage.get("rejected", 0))],
            ],
        )
    else:
        para("Rules v2 did not run for this scan.")

    heading("Critical Findings", 2)
    _finding_section(story, scan, "critical", styles)
    heading("High Findings", 2)
    _finding_section(story, scan, "high", styles)
    story.append(PageBreak())
    heading("Medium Findings", 2)
    _finding_section(story, scan, "medium", styles)
    heading("Low Findings", 2)
    _finding_section(story, scan, "low", styles)
    heading("Suppressed Findings", 2)
    _suppressed_section(story, scan, styles)

    heading("Failed Scanners", 2)
    for item in _failed_scanners(scan) or ["No failed scanner runs were recorded."]:
        para(item)
    heading("Untested Areas", 2)
    for item in _untested_areas(scan) or ["No explicit untested areas were recorded."]:
        para(item)
    heading("Qwen Status", 2)
    para(f"{scan.ai_review.status} via {scan.ai_review.provider}. {scan.ai_review.message}")
    heading("Baseline Comparison", 2)
    para(f"Persisted or computed drift events: {baseline.get('summary', {}).get('total_drift_events', 0)}.")
    for event in (baseline.get("drift_events") or [])[:12]:
        para(str(event.get("message") or event.get("event_type") or event.get("type") or "Drift event recorded."))
    heading("Privacy Warnings", 2)
    for item in _privacy_warnings(scan):
        para(item)
    heading("Staging Warnings", 2)
    for item in _staging_warnings(scan):
        para(item)
    heading("Limitations", 2)
    for item in _limitations(scan):
        para(item)
    heading("Methodology", 2)
    for item in _methodology():
        para(item)
    heading("Reproducibility Metadata", 2)
    _table(
        story,
        [
            ["Scan ID", scan.id],
            ["Started", scan.started_at.isoformat()],
            ["Completed", scan.completed_at.isoformat() if scan.completed_at else "Not completed"],
            ["Report generated", context.generated_at.isoformat()],
            ["Scanner versions", ", ".join(f"{run.scanner} {run.version}" for run in scan.scanner_runs) or "None recorded"],
            ["Model", scan.ai_review.model or "None recorded"],
        ],
    )

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def _table(story: list[Any], rows: list[list[str]], header: bool = False) -> None:
    safe_rows = [[Paragraph(_redact(cell), getSampleStyleSheet()["BodyText"]) for cell in row] for row in rows]
    table = Table(safe_rows, colWidths=[120, 120, 90, 230][: max(len(row) for row in rows)])
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#999999")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9d9d9")))
    table.setStyle(TableStyle(style))
    story.append(table)
    story.append(Spacer(1, 10))


def _finding_section(story: list[Any], scan: Scan, severity: str, styles: dict[str, Any]) -> None:
    findings = [finding for finding in scan.findings if finding.severity.value == severity and finding.status != "suppressed"]
    if not findings:
        story.append(Paragraph(f"No {severity} findings were recorded.", styles["BodyText"]))
        story.append(Spacer(1, 6))
        return
    for finding in findings:
        story.append(Paragraph(_redact(f"{finding.title} ({finding.confidence.value})"), styles["Heading3"]))
        for line in wrap(_redact(finding.description), 110)[:4]:
            story.append(Paragraph(line, styles["BodyText"]))
        _table(
            story,
            [
                ["Category", finding.category],
                ["File", finding.affected_file or "n/a"],
                ["Route", finding.affected_route or "n/a"],
                ["Status", finding.status],
                ["Fingerprint", finding.fingerprint],
                ["Original fingerprint", finding.original_fingerprint or "n/a"],
                ["Recurrence", str(finding.recurrence_count)],
                ["Remediation", finding.remediation],
            ],
        )


def _suppressed_section(story: list[Any], scan: Scan, styles: dict[str, Any]) -> None:
    findings = [finding for finding in scan.findings if finding.status == "suppressed" or finding.suppression is not None]
    if not findings:
        story.append(Paragraph("No suppressed findings were recorded.", styles["BodyText"]))
        story.append(Spacer(1, 6))
        return
    for finding in findings:
        reason = finding.suppression.reason if finding.suppression else "Suppressed"
        story.append(Paragraph(_redact(f"{finding.title}: {reason}"), styles["BodyText"]))


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawString(42, 24, "NOPE - Evidence over vibes")
    canvas.drawRightString(letter[0] - 42, 24, f"Page {doc.page}")
    canvas.restoreState()


def _limitations(scan: Scan) -> list[str]:
    limitations = [
        "NOPE does not claim that the application is fully secure.",
        "Findings are limited to the tested source, target, scanners, and authorization scope.",
        "Dynamic browser and sandbox evidence is included only when those phases are available for the scan.",
    ]
    if scan.status in {"partial", "failed", "cancelled"}:
        limitations.append(f"This scan ended with status '{scan.status}', so coverage is incomplete.")
    if _untested_areas(scan):
        limitations.append("Untested and partially tested areas are listed explicitly in this report.")
    return limitations


def _methodology() -> list[str]:
    return [
        "Deterministic scanners and custom rules provide the primary evidence.",
        "Scanner output is normalized into canonical NOPE findings with severity, confidence, location, and remediation.",
        "Rules v2 uses broad candidate detection, evidence correlation, and a promotion gate; withheld candidates are not reported as confirmed vulnerabilities.",
        "Qwen may assist with explanation or reasoning, but deterministic evidence remains authoritative.",
        "Secret-like values are redacted before report rendering.",
        "Reproducibility metadata records scan identity, commit, coverage, scanner versions, and generation time.",
    ]


def render_report(scan: Scan, fmt: str, context: ReportContext | None = None) -> tuple[str, str | bytes]:
    if fmt == "json":
        return "application/json", json.dumps(report_json(scan, context), indent=2)
    if fmt == "md":
        return "text/markdown", report_markdown(scan, context)
    if fmt == "sarif":
        return "application/sarif+json", json.dumps(report_sarif(scan, context), indent=2)
    if fmt == "pdf":
        return "application/pdf", report_pdf(scan, context)
    raise ValueError("Unsupported report format.")
