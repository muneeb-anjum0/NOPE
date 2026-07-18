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


def _original_text(value: object) -> str | None:
    return str(value) if value is not None else None


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
    end_line: int | None = None,
    rule_id: str | None = None,
    remediation: str | None = None,
    confidence: Confidence = Confidence.medium,
    original_severity: object = None,
    original_confidence: object = None,
    package: str | None = None,
    cve: str | None = None,
    route: str | None = None,
    endpoint: str | None = None,
    symbol: str | None = None,
) -> Finding:
    fp = _fingerprint(scanner, rule_id, title, file, line)
    evidence = Evidence(
        source=scanner,
        file=file,
        line=line,
        end_line=end_line or line,
        route=route,
        endpoint=endpoint,
        symbol=symbol,
        package=package,
        cve=cve,
        message=f"{rule_id + ': ' if rule_id else ''}{description}",
    )
    return Finding(
        fingerprint=fp,
        scanner=scanner,
        original_rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        original_severity=_original_text(original_severity),
        confidence=confidence,
        original_confidence=_original_text(original_confidence),
        category=category,
        affected_file=file,
        start_line=line,
        end_line=end_line or line,
        affected_route=route,
        endpoint=endpoint,
        symbol=symbol,
        package=package,
        cve=cve,
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


def _first_match(root: Path, patterns: list[str]) -> Path | None:
    for pattern in patterns:
        matches = sorted(root.rglob(pattern))
        if matches:
            return matches[0]
    return None


def _dependency_path(value: object) -> str | None:
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for key in ("path", "module", "package", "name"):
                    if item.get(key):
                        parts.append(str(item[key]))
                        break
        return " > ".join(parts) if parts else None
    if isinstance(value, str):
        return value
    return None


def _fixed_version(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        strings = [str(item) for item in value if item]
        return ", ".join(strings) if strings else None
    if isinstance(value, dict):
        if value.get("version"):
            return str(value["version"])
        if value.get("name"):
            return str(value["name"])
    return None


def _dependency_finding(
    *,
    scanner: str,
    package: str,
    advisory: str,
    title: str,
    severity: object,
    file: str | None = None,
    installed_version: object = None,
    fixed_version: object = None,
    dependency_path: object = None,
    description: str | None = None,
) -> Finding:
    fixed = _fixed_version(fixed_version)
    path = _dependency_path(dependency_path)
    version_text = f" Installed version: {installed_version}." if installed_version else ""
    path_text = f" Dependency path: {path}." if path else ""
    fix_text = f" Fixed version: {fixed}." if fixed else ""
    body = (description or title or f"Vulnerable dependency {package}.") + version_text + path_text + fix_text
    remediation = f"Upgrade {package}"
    if fixed:
        remediation += f" to {fixed}"
    remediation += " or remove the vulnerable dependency."
    return _finding(
        scanner=scanner,
        rule_id=advisory,
        title=f"{package}: {advisory}",
        description=body,
        severity=_severity(severity, Severity.high),
        original_severity=severity,
        confidence=Confidence.high,
        category="Dependencies",
        file=file,
        package=package,
        cve=advisory,
        remediation=remediation,
    )


def _json_lines(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = load_json_or_none(line)
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


class ScannerPlugin:
    name = "base"
    command = ""
    coverage_categories: list[str] = []
    supported_markers: list[str] = []
    required_markers: list[str] = []
    network_required = False
    machine_readable_output = "json"
    resource_requirements: dict[str, str] = {
        "timeout": "settings.max_scanner_seconds",
        "stdout_stderr_limit": "settings.max_scanner_output_bytes",
    }
    acceptable_exit_codes = {0, 1}

    def detect_applicability(self, root: Path) -> bool:
        markers = self.required_markers or self.supported_markers
        if not markers:
            return True
        return any(list(root.rglob(marker)) for marker in markers)

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
            "required_markers": self.required_markers,
            "network_required": self.network_required,
            "machine_readable_output": self.machine_readable_output,
            "resource_requirements": self.resource_requirements,
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
                    "NPM_CONFIG_IGNORE_SCRIPTS": "true",
                    "npm_config_ignore_scripts": "true",
                    "YARN_ENABLE_SCRIPTS": "0",
                },
            )
            findings = self.parse_results(result.stdout, result.stderr, root)
            stdout = _bounded_redacted(result.stdout, settings.max_scanner_output_bytes)
            stderr = _bounded_redacted(result.stderr, settings.max_scanner_output_bytes)
            return (
                ScannerRun(
                    scanner=self.name,
                    status="passed" if result.returncode in self.acceptable_exit_codes else "failed",
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
                    original_severity=extra.get("severity"),
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
                    original_severity="HIGH",
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
                            original_severity="HIGH",
                            confidence=Confidence.high,
                            category="Dependencies",
                            file=file,
                            package=package_name,
                            cve=vuln_id,
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
                        original_severity=item.get("Severity"),
                        confidence=Confidence.high,
                        category="Dependencies",
                        file=file,
                        package=package,
                        cve=vuln_id,
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
                        original_severity=item.get("Severity"),
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
                        original_severity=item.get("Severity"),
                        confidence=Confidence.medium,
                        category="CI/CD",
                        file=file,
                        remediation=str(item.get("Resolution") or "Review and remediate the misconfiguration."),
                    )
                )
        return findings


class NpmAuditPlugin(ScannerPlugin):
    name = "npm audit"
    command = "npm"
    coverage_categories = ["Dependencies"]
    supported_markers = ["package.json", "package-lock.json"]
    required_markers = ["package-lock.json"]
    network_required = True

    def build_command(self, root: Path) -> list[str]:
        return ["npm", "audit", "--json", "--package-lock-only", "--ignore-scripts"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        findings: list[Finding] = []
        lockfile = _relative(root, str(_first_match(root, ["package-lock.json"]))) if _first_match(root, ["package-lock.json"]) else None
        for package_name, vuln_value in _as_dict(data.get("vulnerabilities")).items():
            vuln = _as_dict(vuln_value)
            via_items = _as_list(vuln.get("via")) or [vuln]
            for via in via_items:
                advisory = _as_dict(via)
                if not advisory:
                    advisory_id = str(via)
                    title = f"Vulnerable dependency via {advisory_id}"
                    severity = vuln.get("severity")
                    fixed = _as_dict(vuln.get("fixAvailable")).get("version")
                else:
                    advisory_id = str(advisory.get("source") or advisory.get("url") or advisory.get("name") or package_name)
                    title = str(advisory.get("title") or vuln.get("title") or f"Vulnerable dependency: {package_name}")
                    severity = advisory.get("severity") or vuln.get("severity")
                    fixed = _as_dict(vuln.get("fixAvailable")).get("version") or advisory.get("patched_versions")
                findings.append(
                    _dependency_finding(
                        scanner=self.name,
                        package=str(package_name),
                        advisory=advisory_id,
                        title=title,
                        severity=severity,
                        file=lockfile,
                        installed_version=vuln.get("range"),
                        fixed_version=fixed,
                        dependency_path=vuln.get("nodes") or vuln.get("effects"),
                        description=title,
                    )
                )
        for advisory_id, value in _as_dict(data.get("advisories")).items():
            advisory = _as_dict(value)
            package = str(advisory.get("module_name") or advisory.get("name") or "dependency")
            findings.append(
                _dependency_finding(
                    scanner=self.name,
                    package=package,
                    advisory=str(advisory.get("cves", [advisory_id])[0] if isinstance(advisory.get("cves"), list) and advisory.get("cves") else advisory_id),
                    title=str(advisory.get("title") or f"Vulnerable dependency: {package}"),
                    severity=advisory.get("severity"),
                    file=lockfile,
                    installed_version=advisory.get("vulnerable_versions"),
                    fixed_version=advisory.get("patched_versions"),
                    dependency_path=[path for finding in _as_list(advisory.get("findings")) for path in _as_list(_as_dict(finding).get("paths"))],
                    description=advisory.get("overview"),
                )
            )
        return findings


class PnpmAuditPlugin(NpmAuditPlugin):
    name = "pnpm audit"
    command = "pnpm"
    supported_markers = ["package.json", "pnpm-lock.yaml"]
    required_markers = ["pnpm-lock.yaml"]

    def build_command(self, root: Path) -> list[str]:
        return ["pnpm", "audit", "--json"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        lockfile = _relative(root, str(_first_match(root, ["pnpm-lock.yaml"]))) if _first_match(root, ["pnpm-lock.yaml"]) else None
        findings: list[Finding] = []
        for advisory_id, value in _as_dict(data.get("advisories") or data.get("vulnerabilities")).items():
            advisory = _as_dict(value)
            package = str(advisory.get("module_name") or advisory.get("name") or advisory_id)
            findings.append(
                _dependency_finding(
                    scanner=self.name,
                    package=package,
                    advisory=str(advisory.get("cves", [advisory_id])[0] if isinstance(advisory.get("cves"), list) and advisory.get("cves") else advisory_id),
                    title=str(advisory.get("title") or f"Vulnerable dependency: {package}"),
                    severity=advisory.get("severity"),
                    file=lockfile,
                    installed_version=advisory.get("vulnerable_versions"),
                    fixed_version=advisory.get("patched_versions"),
                    dependency_path=[path for finding in _as_list(advisory.get("findings")) for path in _as_list(_as_dict(finding).get("paths"))],
                    description=advisory.get("overview") or advisory.get("title"),
                )
            )
        return findings


class YarnAuditPlugin(NpmAuditPlugin):
    name = "yarn audit"
    command = "yarn"
    supported_markers = ["package.json", "yarn.lock"]
    required_markers = ["yarn.lock"]

    def build_command(self, root: Path) -> list[str]:
        if (root / ".yarnrc.yml").exists():
            return ["yarn", "npm", "audit", "--json"]
        return ["yarn", "audit", "--json"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = load_json_or_none(stdout)
        if isinstance(data, dict) and (data.get("vulnerabilities") or data.get("advisories")):
            return super().parse_results(stdout, stderr, root)
        lockfile = _relative(root, str(_first_match(root, ["yarn.lock"]))) if _first_match(root, ["yarn.lock"]) else None
        findings: list[Finding] = []
        for row in _json_lines(stdout):
            if row.get("type") != "auditAdvisory":
                continue
            advisory = _as_dict(_as_dict(row.get("data")).get("advisory"))
            advisory_id = str(advisory.get("cves", [advisory.get("id")])[0] if isinstance(advisory.get("cves"), list) and advisory.get("cves") else advisory.get("id") or advisory.get("url") or "yarn-advisory")
            package = str(advisory.get("module_name") or advisory.get("name") or "dependency")
            findings.append(
                _dependency_finding(
                    scanner=self.name,
                    package=package,
                    advisory=advisory_id,
                    title=str(advisory.get("title") or f"Vulnerable dependency: {package}"),
                    severity=advisory.get("severity"),
                    file=lockfile,
                    installed_version=advisory.get("vulnerable_versions"),
                    fixed_version=advisory.get("patched_versions"),
                    dependency_path=[path for finding in _as_list(advisory.get("findings")) for path in _as_list(_as_dict(finding).get("paths"))],
                    description=advisory.get("overview"),
                )
            )
        return findings


class PipAuditPlugin(ScannerPlugin):
    name = "pip-audit"
    command = "pip-audit"
    coverage_categories = ["Dependencies"]
    supported_markers = ["requirements*.txt", "pyproject.toml", "poetry.lock"]
    required_markers = ["requirements*.txt", "pyproject.toml", "poetry.lock"]
    network_required = True

    def build_command(self, root: Path) -> list[str]:
        requirements = _first_match(root, ["requirements*.txt"])
        if requirements:
            return ["pip-audit", "--format", "json", "--requirement", str(requirements)]
        if _first_match(root, ["poetry.lock"]):
            return ["pip-audit", "--format", "json", "--locked", str(root)]
        return ["pip-audit", "--format", "json", str(root)]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        findings: list[Finding] = []
        manifest = _relative(root, str(_first_match(root, ["requirements*.txt", "pyproject.toml", "poetry.lock"]))) if _first_match(root, ["requirements*.txt", "pyproject.toml", "poetry.lock"]) else None
        for dependency in _as_list(data.get("dependencies")):
            dep = _as_dict(dependency)
            package = str(dep.get("name") or "dependency")
            for vuln in _as_list(dep.get("vulns")):
                item = _as_dict(vuln)
                advisory = str(item.get("id") or (_as_list(item.get("aliases"))[0] if _as_list(item.get("aliases")) else "pip-audit"))
                findings.append(
                    _dependency_finding(
                        scanner=self.name,
                        package=package,
                        advisory=advisory,
                        title=str(item.get("description") or f"Vulnerable dependency: {package}"),
                        severity=item.get("severity") or "high",
                        file=manifest,
                        installed_version=dep.get("version"),
                        fixed_version=item.get("fix_versions"),
                        dependency_path=package,
                        description=item.get("description"),
                    )
                )
        return findings


class DotnetPackageAuditPlugin(ScannerPlugin):
    name = ".NET package audit"
    command = "dotnet"
    coverage_categories = ["Dependencies"]
    supported_markers = ["*.csproj", "*.sln", "packages.lock.json"]
    required_markers = ["*.csproj", "*.sln", "packages.lock.json"]
    network_required = True

    def build_command(self, root: Path) -> list[str]:
        target = _first_match(root, ["*.sln", "*.csproj"])
        command = ["dotnet", "package", "list"]
        if target:
            command.append(str(target))
        return [*command, "--vulnerable", "--include-transitive", "--format", "json"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        findings: list[Finding] = []
        for project in _as_list(data.get("projects")):
            project_file = _relative(root, _as_dict(project).get("path") or _as_dict(project).get("filePath"))
            for framework in _as_list(_as_dict(project).get("frameworks")):
                frame = _as_dict(framework)
                for bucket in ("topLevelPackages", "transitivePackages"):
                    for package_value in _as_list(frame.get(bucket)):
                        package = _as_dict(package_value)
                        package_name = str(package.get("id") or package.get("name") or "dependency")
                        for vuln_value in _as_list(package.get("vulnerabilities")):
                            vuln = _as_dict(vuln_value)
                            advisory = str(vuln.get("advisoryurl") or vuln.get("advisoryUrl") or vuln.get("id") or "dotnet-advisory")
                            findings.append(
                                _dependency_finding(
                                    scanner=self.name,
                                    package=package_name,
                                    advisory=advisory,
                                    title=f"Vulnerable .NET package: {package_name}",
                                    severity=vuln.get("severity"),
                                    file=project_file,
                                    installed_version=package.get("resolvedVersion"),
                                    fixed_version=package.get("latestVersion"),
                                    dependency_path=bucket,
                                    description=f"{package_name} is reported vulnerable by .NET package audit.",
                                )
                            )
        return findings


class CargoAuditPlugin(ScannerPlugin):
    name = "cargo audit"
    command = "cargo"
    coverage_categories = ["Dependencies"]
    supported_markers = ["Cargo.lock", "Cargo.toml"]
    required_markers = ["Cargo.lock"]
    network_required = True

    def build_command(self, root: Path) -> list[str]:
        return ["cargo", "audit", "--json"]

    def health_check(self) -> tuple[bool, str]:
        if not shutil.which("cargo"):
            return False, "cargo was not found on PATH."
        try:
            result = subprocess.run(["cargo", "audit", "--version"], capture_output=True, text=True, timeout=10, check=False)
        except Exception as exc:
            return False, f"cargo-audit version check failed: {exc}"
        if result.returncode == 0:
            return True, "Installed."
        return False, "cargo-audit was not found as a cargo subcommand."

    def version_command(self) -> list[str]:
        return ["cargo", "audit", "--version"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        lockfile = _relative(root, str(_first_match(root, ["Cargo.lock"]))) if _first_match(root, ["Cargo.lock"]) else None
        findings: list[Finding] = []
        for vuln_value in _as_list(_as_dict(data.get("vulnerabilities")).get("list")):
            vuln = _as_dict(vuln_value)
            advisory = _as_dict(vuln.get("advisory"))
            versions = _as_dict(vuln.get("versions"))
            package = str(advisory.get("package") or _as_dict(vuln.get("package")).get("name") or "crate")
            advisory_id = str(advisory.get("id") or (_as_list(advisory.get("aliases"))[0] if _as_list(advisory.get("aliases")) else "cargo-advisory"))
            findings.append(
                _dependency_finding(
                    scanner=self.name,
                    package=package,
                    advisory=advisory_id,
                    title=str(advisory.get("title") or f"Vulnerable crate: {package}"),
                    severity=advisory.get("severity") or advisory.get("cvss") or "high",
                    file=lockfile,
                    installed_version=_as_dict(vuln.get("package")).get("version"),
                    fixed_version=versions.get("patched"),
                    dependency_path=_as_list(vuln.get("versions")),
                    description=advisory.get("description"),
                )
            )
        return findings


class GovulncheckPlugin(ScannerPlugin):
    name = "govulncheck"
    command = "govulncheck"
    coverage_categories = ["Dependencies"]
    supported_markers = ["go.mod", "go.sum"]
    required_markers = ["go.mod"]
    network_required = True

    def build_command(self, root: Path) -> list[str]:
        return ["govulncheck", "-json", "./..."]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        osv_by_id: dict[str, dict[str, Any]] = {}
        findings: list[Finding] = []
        go_mod = _relative(root, str(_first_match(root, ["go.mod"]))) if _first_match(root, ["go.mod"]) else None
        for row in _json_lines(stdout):
            if isinstance(row.get("osv"), dict):
                osv = _as_dict(row["osv"])
                if osv.get("id"):
                    osv_by_id[str(osv["id"])] = osv
            finding = _as_dict(row.get("finding"))
            if not finding:
                continue
            advisory_id = str(finding.get("osv") or finding.get("id") or "go-vuln")
            osv = osv_by_id.get(advisory_id, {})
            trace = _as_list(finding.get("trace"))
            package = "go module"
            if trace:
                first = _as_dict(trace[0])
                package = str(first.get("module") or first.get("package") or package)
            findings.append(
                _dependency_finding(
                    scanner=self.name,
                    package=package,
                    advisory=advisory_id,
                    title=str(osv.get("summary") or finding.get("message") or f"Reachable Go vulnerability: {package}"),
                    severity=osv.get("severity") or "high",
                    file=go_mod,
                    installed_version=_as_dict(trace[0]).get("version") if trace else None,
                    fixed_version=finding.get("fixed_version") or finding.get("fixedVersion"),
                    dependency_path=trace,
                    description=osv.get("details") or osv.get("summary"),
                )
            )
        return findings


class ComposerAuditPlugin(ScannerPlugin):
    name = "composer audit"
    command = "composer"
    coverage_categories = ["Dependencies"]
    supported_markers = ["composer.json", "composer.lock"]
    required_markers = ["composer.lock"]
    network_required = True

    def build_command(self, root: Path) -> list[str]:
        return ["composer", "audit", "--format=json", "--locked"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        lockfile = _relative(root, str(_first_match(root, ["composer.lock"]))) if _first_match(root, ["composer.lock"]) else None
        findings: list[Finding] = []
        for package, advisory_list in _as_dict(data.get("advisories")).items():
            for advisory_value in _as_list(advisory_list):
                advisory = _as_dict(advisory_value)
                advisory_id = str(advisory.get("cve") or advisory.get("advisoryId") or advisory.get("id") or advisory.get("link") or package)
                findings.append(
                    _dependency_finding(
                        scanner=self.name,
                        package=str(package),
                        advisory=advisory_id,
                        title=str(advisory.get("title") or f"Vulnerable Composer package: {package}"),
                        severity=advisory.get("severity") or "high",
                        file=lockfile,
                        fixed_version=advisory.get("patchedVersions") or advisory.get("patched_versions"),
                        dependency_path=package,
                        description=advisory.get("title"),
                    )
                )
        return findings


class BundlerAuditPlugin(ScannerPlugin):
    name = "bundler-audit"
    command = "bundle-audit"
    coverage_categories = ["Dependencies"]
    supported_markers = ["Gemfile", "Gemfile.lock"]
    required_markers = ["Gemfile.lock"]
    network_required = False

    def build_command(self, root: Path) -> list[str]:
        return ["bundle-audit", "check", "--format", "json", "--no-update"]

    def parse_results(self, stdout: str, stderr: str, root: Path) -> list[Finding]:
        data = _as_dict(load_json_or_none(stdout))
        lockfile = _relative(root, str(_first_match(root, ["Gemfile.lock"]))) if _first_match(root, ["Gemfile.lock"]) else None
        findings: list[Finding] = []
        for result_value in _as_list(data.get("results")):
            result = _as_dict(result_value)
            advisory = _as_dict(result.get("advisory"))
            gem = _as_dict(result.get("gem"))
            package = str(gem.get("name") or result.get("gem") or "gem")
            advisory_id = str(advisory.get("cve") or advisory.get("ghsa") or advisory.get("id") or advisory.get("url") or "ruby-advisory")
            findings.append(
                _dependency_finding(
                    scanner=self.name,
                    package=package,
                    advisory=advisory_id,
                    title=str(advisory.get("title") or f"Vulnerable Ruby gem: {package}"),
                    severity=advisory.get("criticality") or advisory.get("severity") or "high",
                    file=lockfile,
                    installed_version=gem.get("version"),
                    fixed_version=advisory.get("patched_versions") or advisory.get("patchedVersions"),
                    dependency_path=package,
                    description=advisory.get("description") or advisory.get("title"),
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
                    original_severity=item.get("severity") or "MEDIUM",
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
                    original_severity=item.get("level"),
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
                    original_severity=item.get("issue_severity"),
                    confidence=_confidence(item.get("issue_confidence"), Confidence.medium),
                    original_confidence=item.get("issue_confidence"),
                    category="Static analysis",
                    file=_relative(root, item.get("filename")),
                    line=item.get("line_number") if isinstance(item.get("line_number"), int) else None,
                    remediation=str(item.get("more_info") or "Review Bandit guidance and fix the unsafe Python pattern."),
                )
            )
        return findings


class ZapBaselinePlugin(ScannerPlugin):
    name = "OWASP ZAP baseline"
    command = "zap-baseline.py"
    coverage_categories = ["Dynamic testing"]

    def detect_applicability(self, root: Path) -> bool:
        return False

    def health_check(self) -> tuple[bool, str]:
        return False, "Not applicable to repository scans; requires a running HTTP target in the dynamic sandbox phase."

    def version(self) -> str:
        return "not applicable to repository scans"

    def build_command(self, root: Path) -> list[str]:
        return []

    def execute(self, root: Path, settings: Settings) -> tuple[ScannerRun, list[Finding]]:
        started = now_utc()
        return (
            ScannerRun(
                scanner=self.name,
                version=self.version(),
                status="skipped",
                coverage_categories=self.coverage_categories,
                started_at=started,
                completed_at=now_utc(),
                message="Not applicable to repository scans; requires a running HTTP target in the dynamic sandbox phase.",
                command=[],
            ),
            [],
        )


def scanner_plugins() -> list[ScannerPlugin]:
    return [
        SemgrepPlugin(),
        GitleaksPlugin(),
        OsvScannerPlugin(),
        TrivyPlugin(),
        NpmAuditPlugin(),
        PnpmAuditPlugin(),
        YarnAuditPlugin(),
        PipAuditPlugin(),
        DotnetPackageAuditPlugin(),
        CargoAuditPlugin(),
        GovulncheckPlugin(),
        ComposerAuditPlugin(),
        BundlerAuditPlugin(),
        CheckovPlugin(),
        HadolintPlugin(),
        BanditPlugin(),
        ZapBaselinePlugin(),
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
