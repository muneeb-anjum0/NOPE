import ipaddress
import re
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

from nope_api.config import Settings
from nope_api.models import AuthorizationScope


SECRET_PATTERNS = [
    re.compile(r"(?i)([\"'](?:api[_-]?key|token|secret|password)[\"']\s*:\s*)[\"'][^\"']{12,}[\"']"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{12,})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----"),
]


def redact(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: f"{m.group(1) if m.groups() else 'secret'}***REDACTED***", redacted)
    return redacted


def is_private_host(hostname: str) -> bool:
    return any(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved for ip in resolve_host_addresses(hostname))


def resolve_host_addresses(hostname: str) -> list[ipaddress._BaseAddress]:
    try:
        ip = ipaddress.ip_address(hostname)
        return [ip]
    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    resolved: list[ipaddress._BaseAddress] = []
    for address in addresses:
        candidate = ipaddress.ip_address(address[4][0])
        if candidate not in resolved:
            resolved.append(candidate)
    return resolved


def validate_resolved_addresses(hostname: str, settings: Settings, *, allow_private: bool = False) -> list[str]:
    addresses = resolve_host_addresses(hostname)
    if not addresses:
        raise HTTPException(status_code=400, detail="Target host could not be resolved.")
    blocked = [ip for ip in addresses if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved]
    if blocked and not (settings.allow_private_url_targets or allow_private):
        raise HTTPException(status_code=400, detail="Private network targets are blocked by default.")
    return [str(ip) for ip in addresses]


def validate_url_scope(
    url: str,
    authorization: AuthorizationScope | None,
    settings: Settings,
) -> AuthorizationScope:
    if authorization is None or not authorization.confirmed:
        raise HTTPException(status_code=400, detail="URL scans require explicit authorization confirmation.")

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Only http and https targets are supported.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URL scans must not include credentials.")

    hostname = parsed.hostname.lower()
    approved_hosts = {host.lower() for host in authorization.approved_hosts}
    if not approved_hosts:
        approved_hosts.add(hostname)
        authorization.approved_hosts = [hostname]
    if hostname not in approved_hosts:
        raise HTTPException(status_code=400, detail="Target host is outside approved scan scope.")

    private = is_private_host(hostname)
    localhost = hostname in {"localhost", "127.0.0.1", "::1"}
    if private and not (settings.allow_private_url_targets or authorization.allow_private_targets):
        raise HTTPException(status_code=400, detail="Private network targets are blocked by default.")
    if localhost and not (settings.allow_localhost_url_targets or authorization.allow_private_targets):
        raise HTTPException(status_code=400, detail="Localhost targets require explicit local sandbox enablement.")

    allowed_ports = {int(port.strip()) for port in settings.url_scan_allowed_ports.split(",") if port.strip().isdigit()}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if allowed_ports and port not in allowed_ports:
        raise HTTPException(status_code=400, detail="Target port is outside the approved scan scope.")
    authorization.approved_hosts = sorted(approved_hosts)
    validate_resolved_addresses(hostname, settings, allow_private=authorization.allow_private_targets)

    return authorization
