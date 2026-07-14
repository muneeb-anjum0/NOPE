import json

from nope_api.models import Scan


def report_json(scan: Scan) -> dict:
    return scan.model_dump(mode="json")


def report_markdown(scan: Scan) -> str:
    lines = [
        f"# NOPE Report: {scan.id}",
        "",
        f"Verdict: {scan.verdict}",
        f"Score: {scan.score}",
        f"Coverage: {scan.coverage_percent}%",
        "",
        "## Scope",
        f"- Mode: {scan.mode.value}",
        f"- Repository: {scan.repository_name or 'Not provided'}",
        f"- Target URL: {scan.target_url or 'Not provided'}",
        "",
        "## Findings",
    ]
    if not scan.findings:
        lines.append("No findings were produced in the tested scope.")
    for finding in scan.findings:
        lines.extend(
            [
                f"### {finding.severity.value.upper()}: {finding.title}",
                f"- Category: {finding.category}",
                f"- Confidence: {finding.confidence.value}",
                f"- File: {finding.affected_file or 'n/a'}",
                f"- Route: {finding.affected_route or 'n/a'}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )
    lines.extend(["## Untested Areas"])
    for record in scan.coverage:
        if record.status.value in {"Not tested", "Failed", "Partial"}:
            lines.append(f"- {record.domain}: {record.status.value} - {record.notes}")
    return "\n".join(lines)


def report_sarif(scan: Scan) -> dict:
    rules = {}
    results = []
    for finding in scan.findings:
        rule_id = finding.cwe or finding.category
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.remediation},
        }
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.affected_file or "target-url"},
                "region": {"startLine": finding.evidence[0].line or 1 if finding.evidence else 1},
            }
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.severity.value in {"critical", "high"} else "warning",
                "message": {"text": finding.title},
                "locations": [location],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "NOPE", "rules": list(rules.values())}},
                "results": results,
                "properties": {"scan_id": scan.id, "verdict": scan.verdict},
            }
        ],
    }


def render_report(scan: Scan, fmt: str) -> tuple[str, str]:
    if fmt == "json":
        return "application/json", json.dumps(report_json(scan), indent=2)
    if fmt == "md":
        return "text/markdown", report_markdown(scan)
    if fmt == "sarif":
        return "application/sarif+json", json.dumps(report_sarif(scan), indent=2)
    raise ValueError("Unsupported report format.")
