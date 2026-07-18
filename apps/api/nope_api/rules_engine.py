import hashlib
import json
import re
from pathlib import Path
from typing import Any

from nope_api.models import Confidence, Evidence, Finding, FindingStatus, Severity, now_utc
from nope_api.security import redact


TEXT_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".go",
    ".java",
    ".cs",
    ".php",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".env",
    ".json",
    ".map",
    ".toml",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
}

SKIP_DIRS = {".git", ".next", "node_modules", "__pycache__", ".pytest_cache", "dist", "build", "coverage"}
MAX_RULE_FILE_BYTES = 512 * 1024


def load_rules() -> list[dict[str, Any]]:
    path = Path(__file__).resolve().parents[3] / "security-packs" / "nope-core-rules.json"
    return json.loads(path.read_text(encoding="utf-8"))


def fingerprint(rule_id: str, file: str, line: int, snippet: str) -> str:
    digest = hashlib.sha256(f"{rule_id}:{file}:{line}:{snippet[:80]}".encode()).hexdigest()
    return digest[:24]


def run_rules(root: Path) -> list[Finding]:
    rules = load_rules()
    findings: list[Finding] = []
    for file in root.rglob("*"):
        if not file.is_file() or file.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if set(file.relative_to(root).parts) & SKIP_DIRS:
            continue
        rel = file.relative_to(root).as_posix()
        with file.open("r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read(MAX_RULE_FILE_BYTES)
        lower_text = text.lower()
        lines = text.splitlines()
        for rule in rules:
            absent = [term.lower() for term in rule.get("requires_absent", [])]
            if absent and any(term in lower_text for term in absent):
                continue
            for pattern in rule["patterns"]:
                regex = re.compile(pattern, re.MULTILINE)
                for match in regex.finditer(text):
                    line_no = text[: match.start()].count("\n") + 1
                    snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else match.group(0)
                    findings.append(
                        Finding(
                            fingerprint=fingerprint(rule["id"], rel, line_no, snippet),
                            scanner="NOPE rules",
                            original_rule_id=rule["id"],
                            nope_rule_id=rule["id"],
                            title=rule["title"],
                            description=rule["description"],
                            severity=Severity(rule["severity"]),
                            original_severity=str(rule["severity"]),
                            confidence=Confidence(rule["confidence"]),
                            original_confidence=str(rule["confidence"]),
                            category=rule["category"],
                            cwe=rule.get("cwe"),
                            owasp=rule.get("owasp"),
                            affected_file=rel,
                            start_line=line_no,
                            end_line=line_no,
                            scanner_sources=["NOPE rules"],
                            evidence=[
                                Evidence(
                                    source=rule["id"],
                                    file=rel,
                                    line=line_no,
                                    end_line=line_no,
                                    snippet=redact(snippet),
                                    message=f"Matched NOPE rule {rule['id']}.",
                                )
                            ],
                            remediation=rule["remediation"],
                            test_guidance=rule.get("test_guidance"),
                            fix_available=True,
                        )
                    )
    return findings


def rule_coverage_categories() -> list[str]:
    return sorted({str(rule.get("category")) for rule in load_rules() if rule.get("category")})


SEVERITY_RANK = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.info: 1,
}

CONFIDENCE_RANK = {
    Confidence.confirmed: 5,
    Confidence.high: 4,
    Confidence.medium: 3,
    Confidence.low: 2,
    Confidence.uncertain: 1,
}


def _norm(value: object) -> str:
    return str(value or "").strip().lower()


def _source_location(finding: Finding) -> tuple[str, int | None]:
    line = finding.start_line or (finding.evidence[0].line if finding.evidence else None)
    return (_norm(finding.affected_file), line)


def correlation_key(finding: Finding) -> str:
    if finding.code_flow_fingerprint:
        return f"codeflow:{_norm(finding.code_flow_fingerprint)}"
    if finding.cve and finding.package:
        return f"dependency:{_norm(finding.package)}:{_norm(finding.cve)}"
    if finding.category.lower() == "secrets":
        file, line = _source_location(finding)
        if file and line:
            return f"secret:{file}:{line}"
    file, line = _source_location(finding)
    if finding.original_rule_id and finding.symbol:
        return f"rule-symbol:{_norm(finding.original_rule_id)}:{_norm(finding.symbol)}"
    if finding.affected_route and finding.title:
        return f"route:{_norm(finding.affected_route)}:{_norm(finding.title)}"
    if file and line:
        return f"location:{file}:{line}"
    if finding.scanner and finding.original_rule_id and file:
        return f"scanner-location:{_norm(finding.scanner)}:{_norm(finding.original_rule_id)}:{file}:{line or ''}"
    return f"fingerprint:{finding.fingerprint}"


def _merge_evidence(existing: list[Evidence], incoming: list[Evidence]) -> list[Evidence]:
    seen = {
        (
            item.source,
            item.file,
            item.line,
            item.route,
            item.endpoint,
            item.symbol,
            item.package,
            item.cve,
            item.message,
        )
        for item in existing
    }
    merged = list(existing)
    for item in incoming:
        key = (
            item.source,
            item.file,
            item.line,
            item.route,
            item.endpoint,
            item.symbol,
            item.package,
            item.cve,
            item.message,
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _merge_finding(existing: Finding, incoming: Finding) -> Finding:
    if SEVERITY_RANK[incoming.severity] > SEVERITY_RANK[existing.severity]:
        existing.severity = incoming.severity
    if CONFIDENCE_RANK[incoming.confidence] > CONFIDENCE_RANK[existing.confidence]:
        existing.confidence = incoming.confidence
    existing.scanner_sources = sorted(set(existing.scanner_sources + incoming.scanner_sources))
    if incoming.scanner and incoming.scanner not in existing.scanner_sources:
        existing.scanner_sources.append(incoming.scanner)
        existing.scanner_sources = sorted(set(existing.scanner_sources))
    existing.evidence = _merge_evidence(existing.evidence, incoming.evidence)
    existing.last_seen = max(existing.last_seen, incoming.last_seen)
    existing.recurrence_count = max(existing.recurrence_count, incoming.recurrence_count, 1)
    existing.raw_artifact_id = existing.raw_artifact_id or incoming.raw_artifact_id
    existing.scanner_run_id = existing.scanner_run_id or incoming.scanner_run_id
    existing.original_rule_id = existing.original_rule_id or incoming.original_rule_id
    existing.nope_rule_id = existing.nope_rule_id or incoming.nope_rule_id
    existing.original_severity = existing.original_severity or incoming.original_severity
    existing.original_confidence = existing.original_confidence or incoming.original_confidence
    existing.cwe = existing.cwe or incoming.cwe
    existing.owasp = existing.owasp or incoming.owasp
    existing.package = existing.package or incoming.package
    existing.cve = existing.cve or incoming.cve
    existing.symbol = existing.symbol or incoming.symbol
    existing.endpoint = existing.endpoint or incoming.endpoint
    existing.affected_route = existing.affected_route or incoming.affected_route
    existing.attack_scenario = existing.attack_scenario or incoming.attack_scenario
    existing.impact = existing.impact or incoming.impact
    if existing.status == "open":
        existing.status = FindingStatus.new.value
    if incoming.status not in {"open", FindingStatus.new.value} and existing.status == FindingStatus.new.value:
        existing.status = incoming.status
    return existing


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        if finding.status == "open":
            finding.status = FindingStatus.new.value
        finding.last_seen = now_utc()
        if finding.start_line is None and finding.evidence:
            finding.start_line = finding.evidence[0].line
        if finding.end_line is None:
            finding.end_line = finding.start_line
        if finding.scanner and finding.scanner not in finding.scanner_sources:
            finding.scanner_sources.append(finding.scanner)
        key = correlation_key(finding)
        existing = merged.get(key)
        if not existing:
            merged[key] = finding
            continue
        _merge_finding(existing, finding)
    return list(merged.values())
