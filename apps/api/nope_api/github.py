from typing import Protocol

from nope_api.models import GitHubStatus
from nope_api.settings_contracts import github_status_from_payload
from nope_api.storage import PostgresStore


class GitHubAdapter(Protocol):
    def status(self, owner_user_id: str) -> GitHubStatus:
        ...

    def list_repositories(self, owner_user_id: str) -> dict:
        ...

    def callback_blocked_detail(self) -> str:
        ...


class BlockedGitHubAdapter:
    def __init__(self, store: PostgresStore) -> None:
        self.store = store

    def status(self, owner_user_id: str) -> GitHubStatus:
        contract = self.store.get_github_contract(owner_user_id)
        return github_status_from_payload(contract["data"] if contract else None)

    def list_repositories(self, owner_user_id: str) -> dict:
        status = self.status(owner_user_id)
        if not status.status.startswith("blocked"):
            return {
                "status": status.status,
                "repositories": self.store.list_github_repository_references(owner_user_id),
            }
        return {"status": status.status, "repositories": [], "message": status.message}

    def callback_blocked_detail(self) -> str:
        return "GitHub callback is registered, but private access is blocked until credentials are supplied and verified."
