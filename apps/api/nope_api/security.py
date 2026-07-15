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
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


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

    return authorization
