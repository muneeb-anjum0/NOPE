from urllib.parse import urljoin, urlparse

import httpx

from nope_api.models import Confidence, CoverageRecord, CoverageStatus, Evidence, Finding, ScannerRun, Severity, now_utc


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS is missing",
    "content-security-policy": "Content Security Policy is missing",
    "x-content-type-options": "X-Content-Type-Options is missing",
    "referrer-policy": "Referrer-Policy is missing",
    "permissions-policy": "Permissions-Policy is missing",
}


def _url_evidence(url: str, message: str) -> Evidence:
    return Evidence(source="NOPE URL scanner", route=url, endpoint=url, message=message)


async def scan_url(url: str) -> tuple[list[Finding], list[ScannerRun], list[CoverageRecord]]:
    started = now_utc()
    findings: list[Finding] = []
    coverage = [
        CoverageRecord(domain="URL scanning", status=CoverageStatus.partial, scanners=["NOPE URL scanner"], notes="Non-destructive header and exposure checks completed."),
        CoverageRecord(domain="Dynamic testing", status=CoverageStatus.partial, scanners=["NOPE URL scanner"], notes="No destructive or authenticated dynamic testing was performed."),
    ]
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=15) as client:
            response = await client.get(url)
            parsed = urlparse(url)
            if response.next_request and response.next_request.url.host != parsed.hostname:
                findings.append(
                    Finding(
                        fingerprint=f"url-open-redirect-{parsed.hostname}",
                        scanner="NOPE URL scanner",
                        original_rule_id="url-open-redirect",
                        title="Target redirects outside approved host",
                        description="The target returned a redirect to a different host. NOPE did not follow it because it is outside the approved scope.",
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        category="URL scope",
                        cwe="CWE-601",
                        affected_route=url,
                        endpoint=url,
                        scanner_sources=["NOPE URL scanner"],
                        evidence=[_url_evidence(url, f"Redirect location: {response.headers.get('location')}")],
                        remediation="Restrict redirects to approved hosts or validate redirect destinations server-side.",
                    )
                )
            headers = {key.lower(): value for key, value in response.headers.items()}
            for header, title in SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append(
                        Finding(
                            fingerprint=f"url-header-{parsed.hostname}-{header}",
                            scanner="NOPE URL scanner",
                            original_rule_id=f"missing-header:{header}",
                            title=title,
                            description=f"The response did not include `{header}`.",
                            severity=Severity.low if header != "content-security-policy" else Severity.medium,
                            confidence=Confidence.high,
                            category="Security headers",
                            affected_route=url,
                            endpoint=url,
                            scanner_sources=["NOPE URL scanner"],
                            evidence=[_url_evidence(url, f"Missing header: {header}")],
                            remediation=f"Configure the application or edge proxy to emit `{header}` with a safe policy.",
                        )
                    )
            if headers.get("access-control-allow-origin") == "*":
                findings.append(
                    Finding(
                        fingerprint=f"url-cors-{parsed.hostname}",
                        scanner="NOPE URL scanner",
                        original_rule_id="wildcard-cors",
                        title="Wildcard CORS allowed on target",
                        description="The target returned `Access-Control-Allow-Origin: *`.",
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        category="CORS",
                        cwe="CWE-942",
                        affected_route=url,
                        endpoint=url,
                        scanner_sources=["NOPE URL scanner"],
                        evidence=[_url_evidence(url, "Access-Control-Allow-Origin: *")],
                        remediation="Restrict CORS to known origins and avoid wildcards for sensitive APIs.",
                    )
                )
            for cookie in response.cookies.jar:
                if not cookie.secure or "httponly" not in cookie._rest:
                    findings.append(
                        Finding(
                            fingerprint=f"url-cookie-{parsed.hostname}-{cookie.name}",
                            scanner="NOPE URL scanner",
                            original_rule_id="cookie-security-flags",
                            title="Cookie missing security flags",
                            description="A cookie appears to be missing Secure or HttpOnly protection.",
                            severity=Severity.medium,
                            confidence=Confidence.medium,
                            category="Cookies",
                            affected_route=url,
                            endpoint=url,
                            scanner_sources=["NOPE URL scanner"],
                            evidence=[_url_evidence(url, f"Cookie {cookie.name} missing Secure or HttpOnly.")],
                            remediation="Set Secure, HttpOnly, SameSite, and narrow domain/path flags for sensitive cookies.",
                        )
                    )

            exposed_paths = ["/.env", "/.git/config", "/server-status", "/swagger.json", "/openapi.json", "/_next/static/"]
            for path in exposed_paths:
                probe = await client.get(urljoin(url, path))
                if probe.status_code == 200 and path not in {"/_next/static/"}:
                    findings.append(
                        Finding(
                            fingerprint=f"url-exposed-{parsed.hostname}-{path}",
                            scanner="NOPE URL scanner",
                            original_rule_id="exposed-sensitive-path",
                            title=f"Potentially exposed path: {path}",
                            description="A commonly sensitive path returned HTTP 200.",
                            severity=Severity.high if path in {"/.env", "/.git/config"} else Severity.medium,
                            confidence=Confidence.medium,
                            category="Staging and exposure",
                            affected_route=urljoin(url, path),
                            endpoint=urljoin(url, path),
                            scanner_sources=["NOPE URL scanner"],
                            evidence=[_url_evidence(urljoin(url, path), f"HTTP {probe.status_code}")],
                            remediation="Remove public access to sensitive files, debug endpoints, and API documentation unless intentionally public.",
                        )
                    )
        run = ScannerRun(scanner="NOPE URL scanner", status="passed", coverage_categories=["URL scanning", "Staging", "Security headers", "Privacy"], started_at=started, completed_at=now_utc(), findings_count=len(findings))
        return findings, [run], coverage
    except Exception as exc:
        return (
            [],
            [ScannerRun(scanner="NOPE URL scanner", status="failed", coverage_categories=["URL scanning"], started_at=started, completed_at=now_utc(), message=str(exc))],
            [CoverageRecord(domain="URL scanning", status=CoverageStatus.failed, scanners=["NOPE URL scanner"], notes=str(exc))],
        )
