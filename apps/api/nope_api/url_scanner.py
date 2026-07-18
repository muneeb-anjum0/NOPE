from urllib.parse import urljoin, urlparse

import httpx

from nope_api.config import Settings, get_settings
from nope_api.models import Confidence, CoverageRecord, CoverageStatus, Evidence, Finding, ScannerRun, Severity, now_utc
from nope_api.security import validate_resolved_addresses


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS is missing",
    "content-security-policy": "Content Security Policy is missing",
    "x-content-type-options": "X-Content-Type-Options is missing",
    "referrer-policy": "Referrer-Policy is missing",
    "permissions-policy": "Permissions-Policy is missing",
}


def _url_evidence(url: str, message: str) -> Evidence:
    return Evidence(source="NOPE URL scanner", route=url, endpoint=url, message=message)


async def _bounded_get(client: httpx.AsyncClient, url: str, settings: Settings) -> httpx.Response:
    async with client.stream("GET", url, follow_redirects=False) as response:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > settings.url_scan_max_response_bytes:
                raise ValueError("URL response exceeded configured maximum size.")
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=bytes(body),
            request=response.request,
            extensions=response.extensions,
        )


def _validate_url_for_probe(url: str, approved_hosts: set[str], settings: Settings) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL probe target must use http or https.")
    hostname = parsed.hostname.lower()
    if hostname not in approved_hosts:
        raise ValueError("URL probe target is outside approved host scope.")
    validate_resolved_addresses(hostname, settings)


async def scan_url(url: str, settings: Settings | None = None) -> tuple[list[Finding], list[ScannerRun], list[CoverageRecord]]:
    settings = settings or get_settings()
    started = now_utc()
    findings: list[Finding] = []
    coverage = [
        CoverageRecord(domain="URL scanning", status=CoverageStatus.partial, scanners=["NOPE URL scanner"], notes="Non-destructive header and exposure checks completed."),
        CoverageRecord(domain="Dynamic testing", status=CoverageStatus.partial, scanners=["NOPE URL scanner"], notes="No destructive or authenticated dynamic testing was performed."),
    ]
    try:
        parsed = urlparse(url)
        approved_hosts = {parsed.hostname.lower()} if parsed.hostname else set()
        _validate_url_for_probe(url, approved_hosts, settings)
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=settings.url_scan_timeout_seconds,
            headers={"user-agent": "NOPE-security-scanner/1.0"},
        ) as client:
            response = await _bounded_get(client, url, settings)
            parsed = urlparse(url)
            location = response.headers.get("location")
            if location:
                redirect_url = urljoin(url, location)
                redirect = urlparse(redirect_url)
                if redirect.hostname != parsed.hostname or settings.url_scan_max_redirects == 0:
                    findings.append(
                        Finding(
                            fingerprint=f"url-open-redirect-{parsed.hostname}",
                            scanner="NOPE URL scanner",
                            original_rule_id="url-open-redirect",
                            title="Target redirects outside approved host",
                            description="The target returned a redirect that NOPE did not follow because redirects are disabled or outside approved scope.",
                            severity=Severity.medium,
                            confidence=Confidence.high,
                            category="URL scope",
                            cwe="CWE-601",
                            affected_route=url,
                            endpoint=url,
                            scanner_sources=["NOPE URL scanner"],
                            evidence=[_url_evidence(url, f"Redirect location: {location}")],
                            remediation="Restrict redirects to approved hosts or validate redirect destinations server-side.",
                        )
                    )
                else:
                    _validate_url_for_probe(redirect_url, approved_hosts, settings)
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
                probe_url = urljoin(url, path)
                _validate_url_for_probe(probe_url, approved_hosts, settings)
                probe = await _bounded_get(client, probe_url, settings)
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
