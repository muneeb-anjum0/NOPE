import json
import os
from hashlib import sha256
import shutil
import subprocess
from pathlib import Path
from typing import Any

from nope_api.config import Settings
from nope_api.models import Confidence, Evidence, Finding, ScannerRun, Severity, now_utc
from nope_api.security import redact


def _relative(root: Path, path: str | None) -> str | None:
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        return path.replace("\\", "/")
    try:
        return str(candidate.relative_to(root)).replace("\\", "/")
    except ValueError:
        return candidate.name


def _fingerprint(scanner: str, *parts: object) -> str:
    payload = "|".join(str(part or "") for part in (scanner, *parts))
    return sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _severity(value: object, default: Severity = Severity.medium) -> Severity:
    normalized = str(value or "").lower()
    if normalized in {"critical", "blocker"}:
        return Severity.critical
    if normalized in {"high", "error"}:
        return Severity.high
    if normalized in {"medium", "warning", "warn", "moderate"}:
        return Severity.medium
    if normalized in {"low", "minor"}:
        return Severity.low
    if normalized in {"info", "informational", "note"}:
        return Severity.info
    return default


def _confidence(value: object, default: Confidence = Confidence.medium) -> Confidence:
    normalized = str(value or "").lower()
    if normalized in {"confirmed", "high"}:
        return Confidence.high if normalized == "high" else Confidence.confirmed
    if normalized == "low":
        return Confidence.low
    if normalized == "medium":
        return Confidence.medium
    return default


def _finding(
    *,
    scanner: str,
    title: str,
    description: str,
    severity: Severity,
    category: str,
    file: str | None = None,
    line: int | None = None,
    rule_id: str | None = None,
    remediation: str | None = None,
    confidence: Confidence = Confidence.medium,
) -> Finding:
    fp = _fingerprint(scanner, rule_id, title, file, line)
    evidence = Evidence(
        source=scanner,
        file=file,
        line=line,
        message=f"{rule_id + ': ' if rule_id else ''}{description}",
    )
    return Finding(
        fingerprint=fp,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        category=category,
        affected_file=file,
        scanner_sources=[scanner],
        evidence=[evidence],
        remediation=remediation or "Review the scanner evidence and apply the scanner-recommended fix.",
    )


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _bounded_redacted(text: str, max_bytes: int) -> str:
    redacted = redact(text or "")
    encoded = redacted.encode("utf-8", errors="ignore")
    if len(encoded) <= max_bytes:
        return redacted
    return encoded[:max_bytes].decode("utf-8", errors="ignore") + "\n[truncated by NOPE]"


def _security_pack_path(*parts: str) -> Path:
    return Path(__file__).resolve().parents[3] / "security-packs" / Path(*parts)


class ScannerPlugin:
    name = "base"
    command = ""
    coverage_categories: list[str] = []
    supported_markers: list[str] = []

    def detect_applicability(self, root: Path) -> bool:
        if not self.supported_markers:
            return True
        return any(list(root.rglob(marker)) for marker in self.supported_markers)

    def health_check(self) -> tuple[bool, str]:
        if not self.command:
            return False, "No command configured."
        if shutil.which(self.command):
            return True, "Installed."
        return False, f"{self.command} was not found on PATH."

    def version_command(self) -> list[str]:
        return [self.command, "--version"]

    def version(self) -> str:
        installed, _ = self.health_check()
        if not installed:
            return "unavailable"
        try:
            result = subprocess.run(
                self.version_command(),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env={**os.environ, "HOME": os.environ.get("HOME") or "/tmp", "SEMGREP_SEND_METRICS": "off"},
            )
        except Exception as exc:
            return f"version check failed: {exc}"
        output = (result.stdout or result.stderr).strip().splitlines()
        return output[0] if output else "unknown"

    def capability(self) -> dict:
        installed, message = self.health_check()
        return {
            "name": self.name,
            "command": self.command,
            "installed": installed,
            "health": message,
            "version": self.version(),
            "coverage_categories": self.coverage_categories,
            "supported_markers": self.supported_markers,
        }

    def execute(self, root: Path, settings: Settings) -> tuple[ScannerRun, list[Finding]]:
        started = now_utc()
        applicable = self.detect_applicability(root)
        installed, message = self.health_check()
        command = self.build_command(root)
        if not applicable:
            return (
                ScannerRun(
                    scanner=self.name,
                    status="skipped",
                    coverage_categories=self.coverage_categories,
                    started_at=started,
                    completed_at=now_utc(),
                    message="Scanner not applicable to detected repository stack.",
                    command=command,
                ),
                [],
            )
        if not installed:
            return (
                ScannerRun(
                    scanner=self.name,
                    status="failed",
                    coverage_categories=self.coverage_categories,
                    started_at=started,
                    completed_at=now_utc(),
                    message=message,
                    command=command,
                ),
                [],
            )
        try:
            result = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=settings.max_scanner_seconds,
                check=False,
                env={
                    **os.environ,
                    "HOME": os.environ.get("HOME") or "/tmp",
                    "SEMGREP_SEND_METRICS": "off",
                },
            )
            findings = self.parse_results(result.stdout, result.stderr, root)
            stdout = _bounded_redacted(result.stdout, settings.max_scanner_output_bytes)
            stderr = _bounded_redacted(result.stderr, settings.max_scanner_output_bytes)
            return (
                ScannerRun(
                    scanner=self.name,
                    status="passed" if result.returncode in {0, 1} else "failed",
                    coverage_categories=self.coverage_categories,
                    started_at=started,
                    completed_at=now_utc(),
                    message=(stderr or stdout)[:500],
                    findings_count=len(findings),
                    command=command,
                    exit_code=result.returncode,
                    raw_stdout=stdout,
                    raw_stderr=stderr,
                ),
                findings,
            )
        except Exception as exc:
            return (
                ScannerRun(
                    scanner=self.name,
                    status="failed",
                    coverage_categories=self.coverage_categories,
                    started_at=started,
                    completed_at=now_utc(),
                    message=f"Scanner failed: {exc}",
                    command=command,
                ),
                [],
            )

    def build_command(self, root: Path) -> list[str]:
        return [self.command]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        return []


class SemgrepPlugin(ScannerPlugin):
    name = "Semgrep"
    command = "semgrep"
    coverage_categories = ["Injection", "Authorization", "Authentication", "Secrets"]
    supported_markers = ["*.js", "*.ts", "*.py", "*.go", "*.java"]

    def build_command(self, root: Path) -> list[str]:
        return [
            "semgrep",
            "scan",
            "--config",
            str(_security_pack_path("semgrep", "nope.yml")),
            "--json",
            "--error",
            "--timeout",
            "60",
            "--metrics",
            "off",
        ]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = load_json_or_none(stdout)
        findings: list[Finding] = []
        for result in _as_list(_as_dict(data).get("results")):
            item = _as_dict(result)
            extra = _as_dict(item.get("extra"))
            rule_id = str(item.get("check_id") or extra.get("fingerprint") or "semgrep")
            file = _relative(root, item.get("path"))
            line = _as_dict(item.get("start")).get("line")
            message = str(extra.get("message") or rule_id)
            findings.append(
                _finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=message,
                    description=message,
                    severity=_severity(extra.get("severity"), Severity.medium),
                    confidence=Confidence.high,
                    category="Static analysis",
                    file=file,
                    line=line if isinstance(line, int) else None,
                    remediation=str(_as_dict(extra.get("metadata")).get("fix") or "Review the Semgrep rule guidance and patch the flagged code path."),
                )
            )
        return findings


class GitleaksPlugin(ScannerPlugin):
    name = "Gitleaks"
    command = "gitleaks"
    coverage_categories = ["Secrets"]

    def build_command(self, root: Path) -> list[str]:
        return [
            "gitleaks",
            "detect",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--no-git",
        ]

    def version_command(self) -> list[str]:
        return ["gitleaks", "version"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = load_json_or_none(stdout)
        findings: list[Finding] = []
        for leak in _as_list(data):
            item = _as_dict(leak)
            rule_id = str(item.get("RuleID") or "gitleaks")
            description = str(item.get("Description") or "Potential secret detected.")
            file = _relative(root, item.get("File"))
            line = item.get("StartLine")
            findings.append(
                _finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=f"Secret detected: {rule_id}",
                    description=description,
                    severity=Severity.high,
                    confidence=Confidence.high,
                    category="Secrets",
                    file=file,
                    line=line if isinstance(line, int) else None,
                    remediation="Rotate the exposed credential, remove it from source history, and replace it with a secret manager reference.",
                )
            )
        return findings


class OsvScannerPlugin(ScannerPlugin):
    name = "OSV-Scanner"
    command = "osv-scanner"
    coverage_categories = ["Dependencies"]
    supported_markers = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "poetry.lock", "go.sum", "Cargo.lock"]

    def build_command(self, root: Path) -> list[str]:
        return ["osv-scanner", "--format", "json", "--recursive", str(root)]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        findings: list[Finding] = []
        for result in _as_list(data.get("results")):
            result_dict = _as_dict(result)
            source = _as_dict(result_dict.get("source"))
            file = _relative(root, source.get("path"))
            for package in _as_list(result_dict.get("packages")):
                package_dict = _as_dict(package)
                package_info = _as_dict(package_dict.get("package"))
                package_name = str(package_info.get("name") or "dependency")
                for vuln in _as_list(package_dict.get("vulnerabilities")):
                    vuln_dict = _as_dict(vuln)
                    vuln_id = str(vuln_dict.get("id") or "osv")
                    summary = str(vuln_dict.get("summary") or f"Vulnerable dependency: {package_name}")
                    findings.append(
                        _finding(
                            scanner=self.name,
                            rule_id=vuln_id,
                            title=f"{package_name}: {vuln_id}",
                            description=summary,
                            severity=Severity.high,
                            confidence=Confidence.high,
                            category="Dependencies",
                            file=file,
                            remediation="Upgrade the affected package to a fixed version or remove the vulnerable dependency.",
                        )
                    )
        return findings


class TrivyPlugin(ScannerPlugin):
    name = "Trivy"
    command = "trivy"
    coverage_categories = ["Dependencies", "Containers", "CI/CD"]

    def build_command(self, root: Path) -> list[str]:
        return [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,secret,misconfig",
            str(root),
        ]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        findings: list[Finding] = []
        for result in _as_list(data.get("Results")):
            result_dict = _as_dict(result)
            file = _relative(root, result_dict.get("Target"))
            for vuln in _as_list(result_dict.get("Vulnerabilities")):
                item = _as_dict(vuln)
                vuln_id = str(item.get("VulnerabilityID") or "trivy-vuln")
                package = str(item.get("PkgName") or "dependency")
                findings.append(
                    _finding(
                        scanner=self.name,
                        rule_id=vuln_id,
                        title=f"{package}: {vuln_id}",
                        description=str(item.get("Title") or item.get("Description") or "Vulnerable dependency detected."),
                        severity=_severity(item.get("Severity"), Severity.high),
                        confidence=Confidence.high,
                        category="Dependencies",
                        file=file,
                        remediation=str(item.get("FixedVersion") or "Upgrade the affected package to a fixed version."),
                    )
                )
            for secret in _as_list(result_dict.get("Secrets")):
                item = _as_dict(secret)
                rule_id = str(item.get("RuleID") or item.get("Title") or "trivy-secret")
                line = item.get("StartLine")
                findings.append(
                    _finding(
                        scanner=self.name,
                        rule_id=rule_id,
                        title=f"Secret detected: {rule_id}",
                        description=str(item.get("Title") or "Secret detected by Trivy."),
                        severity=_severity(item.get("Severity"), Severity.high),
                        confidence=Confidence.high,
                        category="Secrets",
                        file=file,
                        line=line if isinstance(line, int) else None,
                        remediation="Rotate the exposed credential and remove it from source history.",
                    )
                )
            for misconfig in _as_list(result_dict.get("Misconfigurations")):
                item = _as_dict(misconfig)
                rule_id = str(item.get("ID") or "trivy-misconfig")
                findings.append(
                    _finding(
                        scanner=self.name,
                        rule_id=rule_id,
                        title=str(item.get("Title") or rule_id),
                        description=str(item.get("Description") or item.get("Message") or "Infrastructure misconfiguration detected."),
                        severity=_severity(item.get("Severity"), Severity.medium),
                        confidence=Confidence.medium,
                        category="CI/CD",
                        file=file,
                        remediation=str(item.get("Resolution") or "Review and remediate the misconfiguration."),
                    )
                )
        return findings


class CheckovPlugin(ScannerPlugin):
    name = "Checkov"
    command = "checkov"
    coverage_categories = ["CI/CD", "Containers"]
    supported_markers = ["*.tf", "*.yaml", "*.yml", "Dockerfile"]

    def build_command(self, root: Path) -> list[str]:
        return ["checkov", "-d", str(root), "-o", "json", "--quiet", "--skip-download"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        payload = load_json_or_none(stdout)
        failed_checks = []
        if isinstance(payload, dict):
            failed_checks.extend(_as_list(_as_dict(payload.get("results")).get("failed_checks")))
        else:
            for framework in _as_list(payload):
                failed_checks.extend(_as_list(_as_dict(_as_dict(framework).get("results")).get("failed_checks")))
        findings: list[Finding] = []
        for check in failed_checks:
            item = _as_dict(check)
            rule_id = str(item.get("check_id") or "checkov")
            file = _relative(root, item.get("file_path"))
            lines = item.get("file_line_range")
            line = lines[0] if isinstance(lines, list) and lines and isinstance(lines[0], int) else None
            findings.append(
                _finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=str(item.get("check_name") or rule_id),
                    description=str(item.get("check_name") or "Infrastructure policy check failed."),
                    severity=Severity.medium,
                    confidence=Confidence.medium,
                    category="CI/CD",
                    file=file,
                    line=line,
                    remediation=str(item.get("guideline") or "Follow the Checkov guideline for this failed policy."),
                )
            )
        return findings


class HadolintPlugin(ScannerPlugin):
    name = "Hadolint"
    command = "hadolint"
    coverage_categories = ["Containers"]
    supported_markers = ["Dockerfile"]

    def build_command(self, root: Path) -> list[str]:
        return ["hadolint", "-f", "json", *[str(p) for p in root.rglob("Dockerfile")]]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for issue in _as_list(load_json_or_none(stdout)):
            item = _as_dict(issue)
            rule_id = str(item.get("code") or "hadolint")
            findings.append(
                _finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=str(item.get("message") or rule_id),
                    description=str(item.get("message") or "Dockerfile lint issue detected."),
                    severity=_severity(item.get("level"), Severity.low),
                    confidence=Confidence.medium,
                    category="Containers",
                    file=_relative(root, item.get("file")),
                    line=item.get("line") if isinstance(item.get("line"), int) else None,
                    remediation="Update the Dockerfile to satisfy the Hadolint rule.",
                )
            )
        return findings


class BanditPlugin(ScannerPlugin):
    name = "Bandit"
    command = "bandit"
    coverage_categories = ["Injection", "Secrets"]
    supported_markers = ["*.py"]

    def build_command(self, root: Path) -> list[str]:
        return ["bandit", "-r", str(root), "-f", "json"]

    def version_command(self) -> list[str]:
        return ["bandit", "--version"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        findings: list[Finding] = []
        for issue in _as_list(data.get("results")):
            item = _as_dict(issue)
            rule_id = str(item.get("test_id") or "bandit")
            title = str(item.get("test_name") or item.get("issue_text") or rule_id)
            findings.append(
                _finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=title,
                    description=str(item.get("issue_text") or title),
                    severity=_severity(item.get("issue_severity"), Severity.medium),
                    confidence=_confidence(item.get("issue_confidence"), Confidence.medium),
                    category="Static analysis",
                    file=_relative(root, item.get("filename")),
                    line=item.get("line_number") if isinstance(item.get("line_number"), int) else None,
                    remediation=str(item.get("more_info") or "Review Bandit guidance and fix the unsafe Python pattern."),
                )
            )
        return findings


def scanner_plugins() -> list[ScannerPlugin]:
    return [
        SemgrepPlugin(),
        GitleaksPlugin(),
        OsvScannerPlugin(),
        TrivyPlugin(),
        CheckovPlugin(),
        HadolintPlugin(),
        BanditPlugin(),
    ]


def scanner_health() -> dict[str, str]:
    return {plugin.name: plugin.health_check()[1] for plugin in scanner_plugins()}


def scanner_capabilities() -> list[dict]:
    return [plugin.capability() for plugin in scanner_plugins()]


def load_json_or_none(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
