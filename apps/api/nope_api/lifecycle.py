from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from nope_api.models import BaselineState, Finding, FindingStatus, Suppression, now_utc


TERMINAL_LIKE = {
    FindingStatus.fixed.value,
    FindingStatus.verified.value,
    FindingStatus.false_positive.value,
    FindingStatus.accepted_risk.value,
    FindingStatus.suppressed.value,
}

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    FindingStatus.new.value: {
        FindingStatus.confirmed.value,
        FindingStatus.fixing.value,
        FindingStatus.false_positive.value,
        FindingStatus.accepted_risk.value,
        FindingStatus.suppressed.value,
    },
    FindingStatus.confirmed.value: {
        FindingStatus.fixing.value,
        FindingStatus.fixed.value,
        FindingStatus.false_positive.value,
        FindingStatus.accepted_risk.value,
        FindingStatus.suppressed.value,
    },
    FindingStatus.fixing.value: {
        FindingStatus.confirmed.value,
        FindingStatus.fixed.value,
        FindingStatus.accepted_risk.value,
        FindingStatus.suppressed.value,
    },
    FindingStatus.fixed.value: {
        FindingStatus.verified.value,
        FindingStatus.reopened.value,
        FindingStatus.reintroduced.value,
    },
    FindingStatus.verified.value: {
        FindingStatus.reopened.value,
        FindingStatus.reintroduced.value,
    },
    FindingStatus.false_positive.value: {
        FindingStatus.reopened.value,
        FindingStatus.suppressed.value,
    },
    FindingStatus.accepted_risk.value: {
        FindingStatus.reopened.value,
        FindingStatus.suppressed.value,
    },
    FindingStatus.suppressed.value: {
        FindingStatus.reopened.value,
        FindingStatus.reintroduced.value,
    },
    FindingStatus.reopened.value: {
        FindingStatus.confirmed.value,
        FindingStatus.fixing.value,
        FindingStatus.fixed.value,
        FindingStatus.false_positive.value,
        FindingStatus.accepted_risk.value,
        FindingStatus.suppressed.value,
    },
    FindingStatus.reintroduced.value: {
        FindingStatus.confirmed.value,
        FindingStatus.fixing.value,
        FindingStatus.fixed.value,
        FindingStatus.accepted_risk.value,
        FindingStatus.suppressed.value,
    },
}


class LifecycleTransitionRequest(BaseModel):
    status: FindingStatus
    reason: str
    actor: str | None = None
    scope: str = "finding"
    expiry: datetime | None = None
    expected_version: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason")
    @classmethod
    def require_reason(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 3:
            raise ValueError("A lifecycle reason is required.")
        return cleaned

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        cleaned = value.strip().lower().replace(" ", "_")
        if cleaned not in {"finding", "fingerprint", "project", "scanner_rule"}:
            raise ValueError("scope must be one of finding, fingerprint, project, scanner_rule.")
        return cleaned


def normalize_status(value: str | FindingStatus) -> str:
    raw = value.value if isinstance(value, FindingStatus) else str(value)
    if raw == "open":
        return FindingStatus.new.value
    return FindingStatus(raw).value


def validate_transition(current: str, target: str) -> None:
    current_status = normalize_status(current)
    target_status = normalize_status(target)
    if current_status == target_status:
        return
    if target_status not in ALLOWED_TRANSITIONS.get(current_status, set()):
        raise ValueError(f"Invalid finding lifecycle transition: {current_status} -> {target_status}.")


def apply_transition(finding: Finding, request: LifecycleTransitionRequest, *, actor: str) -> Finding:
    target = request.status.value
    validate_transition(finding.status, target)
    now = now_utc()
    finding.status = target
    finding.last_seen = now
    finding.lifecycle_version = max(1, finding.lifecycle_version) + 1
    finding.verified = target == FindingStatus.verified.value
    if target == FindingStatus.fixed.value:
        finding.baseline_state = BaselineState.fixed
    if target == FindingStatus.reintroduced.value:
        finding.baseline_state = BaselineState.reintroduced
    if target in {FindingStatus.reopened.value, FindingStatus.reintroduced.value}:
        finding.suppression = None
    if target == FindingStatus.suppressed.value:
        finding.suppression = Suppression(
            reason=request.reason,
            user=actor,
            actor=actor,
            date=now,
            expiry=request.expiry,
            scope=request.scope,
        )
    elif target != FindingStatus.suppressed.value:
        finding.suppression = None
    return finding
