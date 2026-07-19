from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

import httpx
from fastapi import HTTPException

from nope_api.config import Settings
from nope_api.models import GitHubStatus, now_utc
from nope_api.settings_contracts import decrypt_secret, github_status_from_payload
from nope_api.storage import PostgresStore


class GitHubAdapter(Protocol):
    def status(self, owner_user_id: str) -> GitHubStatus:
        ...

    def list_repositories(self, owner_user_id: str) -> dict[str, Any]:
        ...

    def create_state(self, owner_user_id: str) -> dict[str, str]:
        ...

    def validate_callback(self, owner_user_id: str, state: str, code: str | None = None) -> GitHubStatus:
        ...

    def disconnect(self, owner_user_id: str) -> GitHubStatus:
        ...

    def fetch_repository_archive(self, owner_user_id: str, full_name: str, branch: str | None) -> "GitHubArchive":
        ...


@dataclass(frozen=True)
class GitHubArchive:
    full_name: str
    branch: str
    default_branch: str
    commit_sha: str
    private: bool
    content: bytes
    repository: dict[str, Any]


class GitHubApiError(RuntimeError):
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(message)


class GitHubApiClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self._transport = transport

    def get_json(self, path: str, token: str) -> dict[str, Any] | list[dict[str, Any]]:
        response = self._request("GET", path, token)
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubApiError(502, "GitHub returned a non-JSON response.") from exc

    def get_bytes(self, path: str, token: str) -> bytes:
        response = self._request("GET", path, token)
        return response.content

    def _request(self, method: str, path: str, token: str) -> httpx.Response:
        url = path if path.startswith("http") else f"{self.settings.github_api_base_url.rstrip('/')}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "NOPE-security-scanner",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        with httpx.Client(timeout=self.settings.github_timeout_seconds, follow_redirects=False, transport=self._transport) as client:
            response = client.request(method, url, headers=headers)
        if response.status_code in {401, 403}:
            raise GitHubApiError(response.status_code, "GitHub credentials were rejected or revoked.")
        if response.status_code == 404:
            raise GitHubApiError(404, "GitHub repository, branch, or archive was not found.")
        if response.status_code >= 400:
            raise GitHubApiError(response.status_code, "GitHub request failed.")
        return response


class SecureGitHubAdapter:
    def __init__(self, store: PostgresStore, settings: Settings, client: GitHubApiClient | None = None) -> None:
        self.store = store
        self.settings = settings
        self.client = client or GitHubApiClient(settings)

    def status(self, owner_user_id: str) -> GitHubStatus:
        contract = self.store.get_github_contract(owner_user_id)
        payload = self._payload(contract)
        status = github_status_from_payload(payload)
        status.repositories = self.store.list_github_repository_references(owner_user_id)
        if contract:
            status.connection_id = str(contract["id"])
        return status

    def list_repositories(self, owner_user_id: str) -> dict[str, Any]:
        payload = self._payload(self.store.get_github_contract(owner_user_id))
        token = self._token(payload)
        if not token:
            status = github_status_from_payload(payload)
            return {"status": status.status, "repositories": [], "message": status.message}
        self._ensure_token_fresh(payload)
        try:
            repos = self._fetch_repositories(token)
        except GitHubApiError as exc:
            self._mark_revoked_if_needed(owner_user_id, payload, exc)
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        connection = self.store.save_github_contract(owner_user_id, {**payload, "verified_at": now_utc().isoformat(), "revoked_at": None}, "connected")
        persisted = []
        for repo in repos:
            persisted.append(self.store.upsert_github_repository_reference(str(connection["id"]), _repo_reference(repo)))
        self.store.record_audit_log("github.repositories.listed", owner_user_id, data={"count": len(persisted)})
        return {"status": "connected", "repositories": persisted, "message": "GitHub repositories listed from verified credentials."}

    def create_state(self, owner_user_id: str) -> dict[str, str]:
        existing = self._payload(self.store.get_github_contract(owner_user_id))
        state = secrets.token_urlsafe(32)
        payload = {**existing, "oauth_state": state, "oauth_state_created_at": now_utc().isoformat()}
        self.store.save_github_contract(owner_user_id, payload, github_status_from_payload(payload).status)
        self.store.record_audit_log("github.oauth_state.created", owner_user_id)
        client_id = str(payload.get("client_id") or "")
        callback = str(payload.get("callback_url") or "")
        authorize_url = ""
        if client_id and callback:
            authorize_url = (
                f"{self.settings.github_oauth_authorize_url}?client_id={client_id}"
                f"&redirect_uri={callback}&state={state}&scope=repo"
            )
        return {"state": state, "authorize_url": authorize_url}

    def validate_callback(self, owner_user_id: str, state: str, code: str | None = None) -> GitHubStatus:
        contract = self.store.get_github_contract(owner_user_id)
        payload = self._payload(contract)
        if not payload.get("oauth_state") and not state:
            raise HTTPException(status_code=409, detail="GitHub callback is registered, but private access is blocked until credentials are supplied and verified.")
        if not state or state != payload.get("oauth_state"):
            self.store.record_audit_log("github.callback.rejected", owner_user_id, data={"reason": "state_mismatch"})
            raise HTTPException(status_code=400, detail="GitHub callback state did not match the stored CSRF state.")
        payload.pop("oauth_state", None)
        payload["callback_validated_at"] = now_utc().isoformat()
        if code:
            payload["oauth_code_received"] = True
        status = github_status_from_payload(payload)
        self.store.save_github_contract(owner_user_id, payload, status.status)
        self.store.record_audit_log("github.callback.validated", owner_user_id, data={"code_received": bool(code)})
        return status

    def disconnect(self, owner_user_id: str) -> GitHubStatus:
        payload = self._payload(self.store.get_github_contract(owner_user_id))
        for key in ("access_token", "oauth_state", "oauth_code_received"):
            payload.pop(key, None)
        payload["revoked_at"] = now_utc().isoformat()
        self.store.save_github_contract(owner_user_id, payload, "blocked_token_revoked")
        self.store.delete_github_repository_references(owner_user_id)
        self.store.record_audit_log("github.disconnected", owner_user_id)
        return github_status_from_payload(payload)

    def fetch_repository_archive(self, owner_user_id: str, full_name: str, branch: str | None) -> GitHubArchive:
        payload = self._payload(self.store.get_github_contract(owner_user_id))
        token = self._token(payload)
        if not token:
            raise HTTPException(status_code=409, detail="GitHub credentials are not connected.")
        self._ensure_token_fresh(payload)
        full_name = _validate_full_name(full_name)
        try:
            repo = self._repository(token, full_name)
            _enforce_repository_policy(repo, self.settings)
            selected_branch = branch or str(repo.get("default_branch") or "main")
            commit = self._commit(token, full_name, selected_branch)
            content = self.client.get_bytes(f"/repos/{full_name}/zipball/{selected_branch}", token)
        except GitHubApiError as exc:
            self._mark_revoked_if_needed(owner_user_id, payload, exc)
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        if len(content) > self.settings.github_max_archive_bytes:
            raise HTTPException(status_code=413, detail="GitHub archive exceeds configured maximum size.")
        self.store.record_audit_log(
            "github.repository.archive_downloaded",
            owner_user_id,
            data={"repository": full_name, "branch": selected_branch, "commit_sha": str(commit.get("sha") or "")},
        )
        return GitHubArchive(
            full_name=full_name,
            branch=selected_branch,
            default_branch=str(repo.get("default_branch") or selected_branch),
            commit_sha=str(commit.get("sha") or ""),
            private=bool(repo.get("private")),
            content=content,
            repository=dict(repo),
        )

    def _fetch_repositories(self, token: str) -> list[dict[str, Any]]:
        data = self.client.get_json("/user/repos?per_page=100&type=all&sort=updated", token)
        if not isinstance(data, list):
            raise GitHubApiError(502, "GitHub repository list response had an unexpected shape.")
        return [dict(item) for item in data]

    def _repository(self, token: str, full_name: str) -> dict[str, Any]:
        data = self.client.get_json(f"/repos/{full_name}", token)
        if not isinstance(data, dict):
            raise GitHubApiError(502, "GitHub repository response had an unexpected shape.")
        return data

    def _commit(self, token: str, full_name: str, branch: str) -> dict[str, Any]:
        data = self.client.get_json(f"/repos/{full_name}/commits/{branch}", token)
        if not isinstance(data, dict):
            raise GitHubApiError(502, "GitHub commit response had an unexpected shape.")
        return data

    def _payload(self, contract: dict[str, Any] | None) -> dict[str, Any]:
        payload = dict(contract["data"] if contract else {})
        if contract:
            payload["connection_id"] = str(contract["id"])
        return payload

    def _token(self, payload: dict[str, Any]) -> str | None:
        encrypted = payload.get("access_token")
        return decrypt_secret(self.settings, encrypted) if isinstance(encrypted, dict) else None

    def _ensure_token_fresh(self, payload: dict[str, Any]) -> None:
        expires = payload.get("token_expires_at")
        if not expires:
            return
        parsed = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
        if parsed <= datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="GitHub token has expired.")

    def _mark_revoked_if_needed(self, owner_user_id: str, payload: dict[str, Any], exc: GitHubApiError) -> None:
        if exc.status_code in {401, 403}:
            payload = {**payload, "revoked_at": now_utc().isoformat()}
            self.store.save_github_contract(owner_user_id, payload, "blocked_token_revoked")
            self.store.record_audit_log("github.credentials.revoked", owner_user_id)


def _repo_reference(repo: dict[str, Any]) -> dict[str, Any]:
    full_name = str(repo.get("full_name") or "")
    return {
        "id": f"ghr_{sha256(full_name.encode('utf-8')).hexdigest()[:16]}",
        "full_name": full_name,
        "default_branch": str(repo.get("default_branch") or "main"),
        "private": bool(repo.get("private")),
        "data": {
            "id": repo.get("id"),
            "html_url": repo.get("html_url"),
            "permissions": repo.get("permissions") or {},
            "size": repo.get("size"),
            "archived": repo.get("archived"),
            "pushed_at": repo.get("pushed_at"),
        },
    }


def _validate_full_name(value: str) -> str:
    parts = value.strip().split("/")
    if len(parts) != 2 or not all(parts) or any(part.startswith(".") for part in parts):
        raise HTTPException(status_code=422, detail="Repository must be in owner/name form.")
    return f"{parts[0]}/{parts[1]}"


def _enforce_repository_policy(repo: dict[str, Any], settings: Settings) -> None:
    size_kb = int(repo.get("size") or 0)
    if size_kb > settings.github_max_repository_kb:
        raise HTTPException(status_code=413, detail="GitHub repository exceeds configured size policy.")
    permissions = repo.get("permissions") or {}
    if permissions and not (permissions.get("pull") or permissions.get("admin")):
        raise HTTPException(status_code=403, detail="GitHub token does not have repository read permission.")


def enforce_extracted_repository_policy(root: Path, settings: Settings) -> None:
    if settings.github_submodule_policy == "block" and any(path.name == ".gitmodules" for path in root.rglob(".gitmodules")):
        raise HTTPException(status_code=409, detail="GitHub repository contains submodules, which are blocked by policy.")
    if settings.github_lfs_policy == "block":
        checked = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            checked += 1
            if checked > settings.github_max_file_count:
                raise HTTPException(status_code=413, detail="GitHub repository contains too many files.")
            try:
                sample = path.read_bytes()[:512]
            except OSError:
                continue
            if b"version https://git-lfs.github.com/spec/v1" in sample:
                raise HTTPException(status_code=409, detail="Git LFS pointer files are blocked by policy.")


# Backward compatible name used by older imports.
BlockedGitHubAdapter = SecureGitHubAdapter
