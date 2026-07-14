import json
import shutil
import subprocess
from pathlib import Path

from nope_api.config import Settings
from nope_api.models import Finding, ScannerRun, now_utc


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

    def execute(self, root: Path, settings: Settings) -> tuple[ScannerRun, list[Finding]]:
        started = now_utc()
        applicable = self.detect_applicability(root)
        installed, message = self.health_check()
        if not applicable:
            return (
                ScannerRun(
                    scanner=self.name,
                    status="skipped",
                    coverage_categories=self.coverage_categories,
                    started_at=started,
                    completed_at=now_utc(),
                    message="Scanner not applicable to detected repository stack.",
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
                ),
                [],
            )
        try:
            result = subprocess.run(
                self.build_command(root),
                cwd=root,
                capture_output=True,
                text=True,
                timeout=settings.max_scanner_seconds,
                check=False,
            )
            findings = self.parse_results(result.stdout, result.stderr, root)
            return (
                ScannerRun(
                    scanner=self.name,
                    status="passed" if result.returncode in {0, 1} else "failed",
                    coverage_categories=self.coverage_categories,
                    started_at=started,
                    completed_at=now_utc(),
                    message=(result.stderr or result.stdout)[:500],
                    findings_count=len(findings),
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
        return ["semgrep", "scan", "--config", "auto", "--json", "--error", "--timeout", "60"]


class GitleaksPlugin(ScannerPlugin):
    name = "Gitleaks"
    command = "gitleaks"
    coverage_categories = ["Secrets"]

    def build_command(self, root: Path) -> list[str]:
        return ["gitleaks", "detect", "--source", str(root), "--report-format", "json", "--no-git"]


class OsvScannerPlugin(ScannerPlugin):
    name = "OSV-Scanner"
    command = "osv-scanner"
    coverage_categories = ["Dependencies"]
    supported_markers = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "poetry.lock", "go.sum", "Cargo.lock"]

    def build_command(self, root: Path) -> list[str]:
        return ["osv-scanner", "--format", "json", "--recursive", str(root)]


class TrivyPlugin(ScannerPlugin):
    name = "Trivy"
    command = "trivy"
    coverage_categories = ["Dependencies", "Containers", "CI/CD"]

    def build_command(self, root: Path) -> list[str]:
        return ["trivy", "fs", "--format", "json", "--scanners", "vuln,secret,misconfig", str(root)]


class CheckovPlugin(ScannerPlugin):
    name = "Checkov"
    command = "checkov"
    coverage_categories = ["CI/CD", "Containers"]
    supported_markers = ["*.tf", "*.yaml", "*.yml", "Dockerfile"]

    def build_command(self, root: Path) -> list[str]:
        return ["checkov", "-d", str(root), "-o", "json"]


class HadolintPlugin(ScannerPlugin):
    name = "Hadolint"
    command = "hadolint"
    coverage_categories = ["Containers"]
    supported_markers = ["Dockerfile"]

    def build_command(self, root: Path) -> list[str]:
        return ["hadolint", "-f", "json", *[str(p) for p in root.rglob("Dockerfile")]]


class BanditPlugin(ScannerPlugin):
    name = "Bandit"
    command = "bandit"
    coverage_categories = ["Injection", "Secrets"]
    supported_markers = ["*.py"]

    def build_command(self, root: Path) -> list[str]:
        return ["bandit", "-r", str(root), "-f", "json"]


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


def load_json_or_none(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
