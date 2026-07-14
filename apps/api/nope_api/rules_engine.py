import hashlib
import json
import re
from pathlib import Path
from typing import Any

from nope_api.models import Confidence, Evidence, Finding, Severity
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
    ".toml",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
}


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
        rel = file.relative_to(root).as_posix()
        text = file.read_text(encoding="utf-8", errors="ignore")
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
                            title=rule["title"],
                            description=rule["description"],
                            severity=Severity(rule["severity"]),
                            confidence=Confidence(rule["confidence"]),
                            category=rule["category"],
                            cwe=rule.get("cwe"),
                            owasp=rule.get("owasp"),
                            affected_file=rel,
                            scanner_sources=["NOPE rules"],
                            evidence=[
                                Evidence(
                                    source=rule["id"],
                                    file=rel,
                                    line=line_no,
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


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.fingerprint)
        if not existing:
            merged[finding.fingerprint] = finding
            continue
        existing.scanner_sources = sorted(set(existing.scanner_sources + finding.scanner_sources))
        existing.evidence.extend(finding.evidence)
    return list(merged.values())
