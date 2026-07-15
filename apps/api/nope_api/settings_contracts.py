from __future__ import annotations

import base64
from copy import deepcopy
from hashlib import sha256
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from nope_api.config import Settings
from nope_api.models import GitHubSettings, GitHubStatus, ProjectSettings, SystemSettings, now_utc


SYSTEM_SETTINGS_KEY = "system"
GITHUB_SETTINGS_KEY = "github"
PROJECT_SETTINGS_PREFIX = "project:"
SENSITIVE_MARKER = {"encrypted": True}


def default_system_settings(settings: Settings) -> SystemSettings:
    return SystemSettings(
        qwen_endpoint=settings.qwen_runtime_url,
        runtime="llama.cpp" if settings.ai_provider != "none" else "disabled",
        context=settings.effective_qwen_context_size,
        gpu_layers=settings.effective_qwen_gpu_layers,
        timeout=settings.effective_qwen_timeout_seconds,
        output_limit=settings.effective_qwen_max_output_tokens,
        concurrency=settings.ai_max_concurrent_tasks,
        scanner_timeout=settings.max_scanner_seconds,
        default_scan_mode="full",
        report_defaults=["json", "md", "sarif", "pdf"],
        artifact_limit_mb=512,
        sandbox_limits={
            "memory": settings.sandbox_memory,
            "zap_memory": settings.sandbox_zap_memory,
            "cpus": settings.sandbox_cpus,
            "pids_limit": settings.sandbox_pids_limit,
            "zap_pids_limit": settings.sandbox_zap_pids_limit,
            "timeout_seconds": settings.sandbox_timeout_seconds,
            "zap_timeout_seconds": settings.sandbox_zap_timeout_seconds,
            "tmpfs_size": settings.sandbox_tmpfs_size,
        },
    )


def project_settings_key(project_id: str) -> str:
    return f"{PROJECT_SETTINGS_PREFIX}{project_id}"


def encrypt_secret(settings: Settings, value: str) -> dict[str, Any]:
    cipher = _fernet(settings)
    token = cipher.encrypt(value.encode("utf-8")).decode("ascii")
    return {
        **SENSITIVE_MARKER,
        "ciphertext": token,
        "rotated_at": now_utc().isoformat(),
        "sha256": sha256(value.encode("utf-8")).hexdigest(),
    }


def decrypt_secret(settings: Settings, envelope: dict[str, Any]) -> str | None:
    if not envelope.get("encrypted") or not envelope.get("ciphertext"):
        return None
    try:
        return _fernet(settings).decrypt(str(envelope["ciphertext"]).encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def sanitize_project_settings_payload(raw: dict[str, Any] | None) -> dict[str, Any]:
    payload = deepcopy(raw or {})
    secret = payload.pop("test_identities_secret", None)
    configured = bool(secret and isinstance(secret, dict) and secret.get("encrypted"))
    public_identities = []
    for identity in payload.get("test_identities", []) or []:
        public_identities.append({key: value for key, value in dict(identity).items() if key != "password"})
    payload["test_identities"] = public_identities
    payload["test_identities_configured"] = configured or bool(public_identities)
    return payload


def prepare_project_settings_payload(
    settings: Settings,
    incoming: ProjectSettings,
    existing: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = incoming.model_dump(mode="json")
    existing_secret = (existing or {}).get("test_identities_secret")
    secret_identities = [identity for identity in incoming.test_identities if identity.password]
    public_identities = []
    for identity in incoming.test_identities:
        public_identities.append(
            {
                "label": identity.label,
                "username": identity.username,
                "notes": identity.notes,
            }
        )
    payload["test_identities"] = public_identities
    if secret_identities:
        payload["test_identities_secret"] = encrypt_secret(
            settings,
            "\n".join(f"{item.label}:{item.username or ''}:{item.password or ''}" for item in secret_identities),
        )
    elif existing_secret:
        payload["test_identities_secret"] = existing_secret
    payload.pop("test_identities_configured", None)
    return payload


def prepare_github_payload(settings: Settings, incoming: GitHubSettings, existing: dict[str, Any] | None) -> dict[str, Any]:
    payload = existing.copy() if existing else {}
    public_values = incoming.model_dump(mode="json", exclude={"client_secret", "private_key", "webhook_secret"})
    payload.update({key: value for key, value in public_values.items() if value is not None})
    for key in ("client_secret", "private_key", "webhook_secret"):
        value = getattr(incoming, key)
        if value:
            payload[key] = encrypt_secret(settings, value)
    return payload


def github_status_from_payload(payload: dict[str, Any] | None) -> GitHubStatus:
    data = payload or {}
    credential_state = {
        "app_id": bool(data.get("app_id")),
        "client_id": bool(data.get("client_id")),
        "client_secret": _is_encrypted(data.get("client_secret")),
        "private_key": _is_encrypted(data.get("private_key")),
        "webhook_secret": _is_encrypted(data.get("webhook_secret")),
    }
    has_contract = any(credential_state.values())
    has_required = all(credential_state[item] for item in ("app_id", "client_id", "client_secret", "private_key"))
    status = "blocked_missing_credentials"
    message = "GitHub private repository access is blocked until credentials are supplied."
    if has_required:
        status = "blocked_external_credentials_not_verified"
        message = "GitHub credentials are stored, but real private access remains blocked until OAuth/App verification is completed."
    elif has_contract:
        status = "blocked_incomplete_credentials"
        message = "GitHub contract settings are incomplete; NOPE will not fake repository access."
    return GitHubStatus(
        status=status,
        credential_state=credential_state,
        callback_url=data.get("callback_url"),
        selected_repository=data.get("selected_repository"),
        selected_branch=data.get("selected_branch"),
        message=message,
        repositories=[],
    )


def _is_encrypted(value: Any) -> bool:
    return isinstance(value, dict) and value.get("encrypted") is True and bool(value.get("ciphertext"))


def _fernet(settings: Settings) -> Fernet:
    key = base64.urlsafe_b64encode(sha256(settings.encryption_key.encode("utf-8")).digest())
    return Fernet(key)
