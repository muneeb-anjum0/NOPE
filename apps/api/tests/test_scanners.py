import json
import sys

from nope_api.config import Settings
from nope_api.models import Severity
from nope_api.scanners import BanditPlugin, GitleaksPlugin, ScannerPlugin, SemgrepPlugin, TrivyPlugin


def test_semgrep_parser_normalizes_findings(tmp_path):
    payload = {
        "results": [
            {
                "check_id": "typescript.express.security.audit.xss",
                "path": str(tmp_path / "app.ts"),
                "start": {"line": 12},
                "extra": {"message": "Unescaped user input", "severity": "ERROR"},
            }
        ]
    }

    findings = SemgrepPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == Severity.high
    assert findings[0].affected_file == "app.ts"
    assert findings[0].evidence[0].line == 12


def test_gitleaks_parser_redacts_secret_context(tmp_path):
    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API key",
            "File": str(tmp_path / ".env"),
            "StartLine": 1,
        }
    ]

    findings = GitleaksPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].category == "Secrets"
    assert findings[0].severity == Severity.high
    assert findings[0].affected_file == ".env"


def test_trivy_parser_normalizes_vulnerabilities_and_secrets(tmp_path):
    payload = {
        "Results": [
            {
                "Target": str(tmp_path / "package-lock.json"),
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "left-pad",
                        "Severity": "CRITICAL",
                        "Title": "Prototype pollution",
                    }
                ],
                "Secrets": [{"RuleID": "aws-access-key", "Severity": "HIGH", "StartLine": 4}],
            }
        ]
    }

    findings = TrivyPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert {finding.category for finding in findings} == {"Dependencies", "Secrets"}
    assert any(finding.severity == Severity.critical for finding in findings)


def test_bandit_parser_normalizes_python_issues(tmp_path):
    payload = {
        "results": [
            {
                "filename": str(tmp_path / "app.py"),
                "line_number": 7,
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "issue_text": "Possible hardcoded password",
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
            }
        ]
    }

    findings = BanditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].affected_file == "app.py"
    assert findings[0].severity == Severity.low
    assert findings[0].scanner_sources == ["Bandit"]


class EchoScanner(ScannerPlugin):
    name = "Echo"
    command = sys.executable
    coverage_categories = ["Secrets"]

    def build_command(self, root):
        return [
            sys.executable,
            "-c",
            "import sys; print(\"api_key='sk-test-secret-value'\"); print('warning', file=sys.stderr)",
        ]


def test_scanner_execute_captures_redacted_raw_output(tmp_path):
    run, findings = EchoScanner().execute(tmp_path, Settings(max_scanner_output_bytes=1024))

    assert run.status == "passed"
    assert run.exit_code == 0
    assert findings == []
    assert "***REDACTED***" in run.raw_stdout
    assert "sk-test-secret-value" not in run.raw_stdout
    assert "warning" in run.raw_stderr
