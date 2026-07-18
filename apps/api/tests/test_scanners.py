import json
import sys

from nope_api.config import Settings
from nope_api.models import Severity
from nope_api.scanners import (
    BanditPlugin,
    BundlerAuditPlugin,
    CargoAuditPlugin,
    ComposerAuditPlugin,
    DotnetPackageAuditPlugin,
    GitleaksPlugin,
    GovulncheckPlugin,
    NpmAuditPlugin,
    OsvScannerPlugin,
    PipAuditPlugin,
    PnpmAuditPlugin,
    ScannerPlugin,
    SemgrepPlugin,
    TrivyPlugin,
    YarnAuditPlugin,
    ZapBaselinePlugin,
    scanner_capabilities,
)


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


def test_osv_parser_normalizes_vulnerable_dependencies(tmp_path):
    payload = {
        "results": [
            {
                "source": {"path": str(tmp_path / "package-lock.json")},
                "packages": [
                    {
                        "package": {"name": "lodash"},
                        "vulnerabilities": [
                            {"id": "GHSA-test-0001", "summary": "Prototype pollution"}
                        ],
                    }
                ],
            }
        ]
    }

    findings = OsvScannerPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].affected_file == "package-lock.json"
    assert findings[0].category == "Dependencies"
    assert findings[0].scanner_sources == ["OSV-Scanner"]
    assert findings[0].cve == "GHSA-test-0001"


def test_npm_audit_parser_normalizes_lockfile_vulnerabilities(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    payload = {
        "vulnerabilities": {
            "lodash": {
                "severity": "critical",
                "range": "<4.17.21",
                "nodes": ["node_modules/lodash"],
                "fixAvailable": {"version": "4.17.21"},
                "via": [{"source": "GHSA-35jh-r3h4-6jhm", "title": "Prototype pollution", "severity": "high"}],
            }
        }
    }

    findings = NpmAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "npm audit"
    assert findings[0].package == "lodash"
    assert findings[0].cve == "GHSA-35jh-r3h4-6jhm"
    assert findings[0].affected_file == "package-lock.json"
    assert "Fixed version: 4.17.21" in findings[0].description


def test_pnpm_audit_parser_normalizes_advisories(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'", encoding="utf-8")
    payload = {
        "advisories": {
            "1106913": {
                "module_name": "axios",
                "severity": "high",
                "title": "SSRF",
                "patched_versions": ">=1.8.2",
                "findings": [{"paths": ["app>axios"]}],
            }
        }
    }

    findings = PnpmAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "pnpm audit"
    assert findings[0].package == "axios"
    assert findings[0].affected_file == "pnpm-lock.yaml"
    assert "app>axios" in findings[0].description


def test_yarn_audit_parser_normalizes_classic_ndjson(tmp_path):
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    payload = {
        "type": "auditAdvisory",
        "data": {
            "advisory": {
                "id": 123,
                "module_name": "minimist",
                "severity": "moderate",
                "title": "Prototype pollution",
                "patched_versions": ">=1.2.8",
                "findings": [{"paths": ["cli>minimist"]}],
            }
        },
    }

    findings = YarnAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "yarn audit"
    assert findings[0].severity == Severity.medium
    assert findings[0].package == "minimist"


def test_pip_audit_parser_normalizes_dependency_vulns(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==3.2.0", encoding="utf-8")
    payload = {
        "dependencies": [
            {
                "name": "django",
                "version": "3.2.0",
                "vulns": [{"id": "PYSEC-2024-1", "aliases": ["CVE-2024-0001"], "description": "SQL injection", "fix_versions": ["3.2.25"]}],
            }
        ]
    }

    findings = PipAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "pip-audit"
    assert findings[0].package == "django"
    assert findings[0].cve == "PYSEC-2024-1"
    assert "3.2.25" in findings[0].remediation


def test_dotnet_package_audit_parser_normalizes_vulnerabilities(tmp_path):
    payload = {
        "projects": [
            {
                "path": str(tmp_path / "App.csproj"),
                "frameworks": [
                    {
                        "topLevelPackages": [
                            {
                                "id": "Newtonsoft.Json",
                                "resolvedVersion": "12.0.1",
                                "vulnerabilities": [{"severity": "high", "advisoryurl": "https://github.com/advisories/GHSA-test"}],
                            }
                        ]
                    }
                ],
            }
        ]
    }

    findings = DotnetPackageAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == ".NET package audit"
    assert findings[0].package == "Newtonsoft.Json"
    assert findings[0].affected_file == "App.csproj"


def test_cargo_audit_parser_normalizes_advisories(tmp_path):
    (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    payload = {
        "vulnerabilities": {
            "list": [
                {
                    "advisory": {"id": "RUSTSEC-2024-0001", "package": "time", "title": "Soundness issue", "severity": "medium"},
                    "package": {"name": "time", "version": "0.1.0"},
                    "versions": {"patched": [">=0.1.45"]},
                }
            ]
        }
    }

    findings = CargoAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "cargo audit"
    assert findings[0].cve == "RUSTSEC-2024-0001"
    assert findings[0].package == "time"


def test_govulncheck_parser_normalizes_json_lines(tmp_path):
    (tmp_path / "go.mod").write_text("module app", encoding="utf-8")
    stdout = "\n".join(
        [
            json.dumps({"osv": {"id": "GO-2024-0001", "summary": "Request smuggling", "details": "reachable vuln"}}),
            json.dumps({"finding": {"osv": "GO-2024-0001", "trace": [{"module": "golang.org/x/net", "version": "v0.1.0", "package": "golang.org/x/net/http2"}], "fixed_version": "v0.2.0"}}),
        ]
    )

    findings = GovulncheckPlugin().parse_results(stdout, "", tmp_path)

    assert findings[0].scanner == "govulncheck"
    assert findings[0].package == "golang.org/x/net"
    assert findings[0].affected_file == "go.mod"


def test_composer_audit_parser_normalizes_advisories(tmp_path):
    (tmp_path / "composer.lock").write_text("{}", encoding="utf-8")
    payload = {
        "advisories": {
            "symfony/http-foundation": [
                {"cve": "CVE-2024-1234", "title": "Header issue", "severity": "high", "patchedVersions": ">=6.4.0"}
            ]
        }
    }

    findings = ComposerAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "composer audit"
    assert findings[0].package == "symfony/http-foundation"
    assert findings[0].cve == "CVE-2024-1234"


def test_bundler_audit_parser_normalizes_results(tmp_path):
    (tmp_path / "Gemfile.lock").write_text("", encoding="utf-8")
    payload = {
        "results": [
            {
                "gem": {"name": "rack", "version": "2.2.0"},
                "advisory": {"cve": "CVE-2024-2222", "title": "XSS", "criticality": "high", "patched_versions": [">=2.2.8"]},
            }
        ]
    }

    findings = BundlerAuditPlugin().parse_results(json.dumps(payload), "", tmp_path)

    assert findings[0].scanner == "bundler-audit"
    assert findings[0].package == "rack"
    assert findings[0].cve == "CVE-2024-2222"


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


def test_ecosystem_plugins_build_controlled_commands(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text("", encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "App.csproj").write_text("<Project />", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    (tmp_path / "go.mod").write_text("module app", encoding="utf-8")
    (tmp_path / "composer.lock").write_text("{}", encoding="utf-8")
    (tmp_path / "Gemfile.lock").write_text("", encoding="utf-8")

    commands = [
        NpmAuditPlugin().build_command(tmp_path),
        PnpmAuditPlugin().build_command(tmp_path),
        YarnAuditPlugin().build_command(tmp_path),
        PipAuditPlugin().build_command(tmp_path),
        DotnetPackageAuditPlugin().build_command(tmp_path),
        CargoAuditPlugin().build_command(tmp_path),
        GovulncheckPlugin().build_command(tmp_path),
        ComposerAuditPlugin().build_command(tmp_path),
        BundlerAuditPlugin().build_command(tmp_path),
    ]

    flat = " ".join(" ".join(command) for command in commands)
    assert "install" not in flat
    assert "run" not in flat
    assert "--json" in NpmAuditPlugin().build_command(tmp_path)
    assert "--ignore-scripts" in NpmAuditPlugin().build_command(tmp_path)
    assert "--no-update" in BundlerAuditPlugin().build_command(tmp_path)


def test_applicable_missing_ecosystem_tool_reports_unavailable(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(NpmAuditPlugin, "command", "definitely-missing-npm")

    run, findings = NpmAuditPlugin().execute(tmp_path, Settings())

    assert run.status == "failed"
    assert "was not found on PATH" in run.message
    assert run.coverage_categories == ["Dependencies"]
    assert findings == []


def test_scanner_capabilities_include_versions_and_coverage():
    capabilities = scanner_capabilities()
    semgrep = next(item for item in capabilities if item["name"] == "Semgrep")
    npm = next(item for item in capabilities if item["name"] == "npm audit")

    assert "installed" in semgrep
    assert "version" in semgrep
    assert "Secrets" in semgrep["coverage_categories"]
    assert npm["required_markers"] == ["package-lock.json"]
    assert npm["network_required"] is True
    assert npm["machine_readable_output"] == "json"


def test_zap_baseline_is_explicitly_not_applicable_to_repository_scans(tmp_path):
    run, findings = ZapBaselinePlugin().execute(tmp_path, Settings())

    assert run.status == "skipped"
    assert run.scanner == "OWASP ZAP baseline"
    assert "Not applicable to repository scans" in run.message
    assert run.coverage_categories == ["Dynamic testing"]
    assert findings == []
