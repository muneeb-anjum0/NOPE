from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from nope_api.models import Confidence, Evidence, Finding


ValidationState = Literal["promoted", "needs_context", "rejected"]


GENERATED_PARTS = {
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
}
GENERATED_SUFFIXES = (".min.js", ".bundle.js", ".chunk.js")
MAX_CONTEXT_BYTES = 384 * 1024
CONTEXT_RADIUS = 45

DB_ACCESS_RE = re.compile(
    r"\b(findUnique|findFirst|findMany|select|insert|update|delete|from|where|"
    r"prisma|supabase|db\.|sql`|query)\b",
    re.IGNORECASE,
)
CALLER_ID_RE = re.compile(
    r"\b(params|param|searchParams|query|request|req\.|body|slug|uuid|"
    r"invoiceId|userId|tenantId|id)\b",
    re.IGNORECASE,
)
OWNER_SCOPE_RE = re.compile(
    r"\b(ownerId|owner_id|tenantId|tenant_id|organizationId|organisationId|orgId|"
    r"accountId|userId|user_id|auth\.uid|session\.user|currentUser|requireUser|"
    r"getUser|requireAuth|withAuth|policy|rls)\b",
    re.IGNORECASE,
)
ROUTE_SOURCE_RE = re.compile(
    r"(^|/)(app/api|pages/api|api|routes|server)(/|$)|"
    r"(\+server|route)\.(ts|tsx|js|jsx|py)$",
    re.IGNORECASE,
)
SECRET_SIGNAL_RE = re.compile(
    r"(secret|token|api[_-]?key|private[_-]?key|password|passwd|bearer|"
    r"AKIA[0-9A-Z]{16}|-----BEGIN)",
    re.IGNORECASE,
)
CLIENT_AUTH_RE = re.compile(
    r"\b(localStorage\.(?:getItem|setItem)\(['\"](?:role|isAdmin)|"
    r"(?:body|query|params)\.(?:role|tenantId|ownerId|isAdmin))",
    re.IGNORECASE,
)


@dataclass
class FileContext:
    path: str
    text: str = ""
    window: str = ""
    exists: bool = False
    too_large: bool = False
    generated: bool = False


@dataclass
class ValidationDecision:
    state: ValidationState
    finding: Finding
    reasons: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {
            "state": self.state,
            "fingerprint": self.finding.fingerprint,
            "title": self.finding.title,
            "file": self.finding.affected_file,
            "line": self.finding.start_line,
            "scanner": self.finding.scanner,
            "rule": self.finding.nope_rule_id or self.finding.original_rule_id,
            "reasons": self.reasons,
        }


def validate_findings(
    findings: list[Finding], root: Path | None = None
) -> tuple[list[Finding], list[dict[str, object]]]:
    cache: dict[str, FileContext] = {}
    decisions = [_validate_finding(finding, root, cache) for finding in findings]
    promoted = [
        _mark_promoted(decision.finding, decision.reasons)
        for decision in decisions
        if decision.state == "promoted"
    ]
    return promoted, [decision.summary() for decision in decisions]


def validation_counts(decisions: list[dict[str, object]]) -> dict[str, int]:
    counts = {"promoted": 0, "needs_context": 0, "rejected": 0}
    for decision in decisions:
        state = str(decision.get("state") or "")
        if state in counts:
            counts[state] += 1
    return counts


def _validate_finding(
    finding: Finding, root: Path | None, cache: dict[str, FileContext]
) -> ValidationDecision:
    context = _load_context(finding, root, cache)
    category = (finding.category or "").lower()
    title = finding.title.lower()
    rule_id = (finding.nope_rule_id or finding.original_rule_id or "").lower()

    if root is None or not finding.affected_file:
        return ValidationDecision(
            "promoted",
            finding,
            ["Non-repository or URL evidence is already scoped by its scanner."],
        )

    if "depend" in category or finding.cve or finding.package:
        return ValidationDecision(
            "promoted",
            finding,
            ["Dependency evidence is structured by package/CVE identity."],
        )

    if "secret" in category:
        return _validate_secret(finding, context)

    if _is_authorization_like(category, title, rule_id):
        return _validate_authorization(finding, context)

    if context.generated and finding.confidence in {Confidence.uncertain, Confidence.low}:
        return ValidationDecision(
            "needs_context",
            finding,
            [
                "Generated or vendor output with low-confidence evidence is retained "
                "as a candidate only."
            ],
        )

    if not context.exists:
        return ValidationDecision(
            "needs_context",
            finding,
            ["Affected file was unavailable for context validation."],
        )

    return ValidationDecision(
        "promoted",
        finding,
        ["Scanner evidence was context-checked and no contradiction was found."],
    )


def _validate_secret(finding: Finding, context: FileContext) -> ValidationDecision:
    evidence_text = _evidence_text(finding)
    text = "\n".join([evidence_text, context.window])
    if SECRET_SIGNAL_RE.search(text):
        reason = (
            "Secret-like token, key, credential, or private-key evidence was present "
            "in the matched context."
        )
        if context.generated:
            reason += (
                " Generated output is allowed for secrets because bundled credentials "
                "are still ship-impacting."
            )
        return ValidationDecision("promoted", finding, [reason])
    return ValidationDecision(
        "needs_context",
        finding,
        ["Secret category did not include a concrete token/key signal in bounded context."],
    )


def _validate_authorization(finding: Finding, context: FileContext) -> ValidationDecision:
    evidence_text = _evidence_text(finding)
    combined = "\n".join([finding.title, finding.description, evidence_text, context.window])
    rule_id = (finding.nope_rule_id or finding.original_rule_id or "").upper()

    if rule_id == "NOPE-AUTHZ-002" or CLIENT_AUTH_RE.search(combined):
        if context.generated:
            return ValidationDecision(
                "needs_context",
                finding,
                [
                    "Client-controlled authorization evidence is in generated output; "
                    "source context is required before promotion."
                ],
            )
        if CLIENT_AUTH_RE.search(combined):
            return ValidationDecision(
                "promoted",
                finding,
                [
                    "Source context shows role, tenant, owner, or admin authority being "
                    "read from request-controlled or browser-controlled state."
                ],
            )

    if context.generated:
        return ValidationDecision(
            "needs_context",
            finding,
            [
                "Authorization/IDOR candidate is in generated or bundled output; "
                "source route/data-access context is required before promotion."
            ],
        )
    if not context.exists:
        return ValidationDecision(
            "needs_context",
            finding,
            ["Authorization/IDOR candidate could not be tied back to a readable source file."],
        )

    has_route_source = bool(ROUTE_SOURCE_RE.search(context.path))
    has_db_access = bool(DB_ACCESS_RE.search(combined))
    has_caller_id = bool(CALLER_ID_RE.search(combined))
    has_owner_scope = bool(OWNER_SCOPE_RE.search(context.window))

    if has_owner_scope and has_db_access:
        return ValidationDecision(
            "rejected",
            finding,
            [
                "Nearby data-access context already contains owner, tenant, authenticated-user, "
                "policy, or RLS scope signals."
            ],
        )
    if has_route_source and has_db_access and has_caller_id:
        return ValidationDecision(
            "promoted",
            finding,
            [
                "Source route/data-access context shows caller-controlled lookup evidence "
                "without nearby owner/tenant scope."
            ],
        )
    missing: list[str] = []
    if not has_route_source:
        missing.append("source route/server file")
    if not has_db_access:
        missing.append("data-access sink")
    if not has_caller_id:
        missing.append("caller-controlled identifier")
    return ValidationDecision(
        "needs_context",
        finding,
        [f"Authorization/IDOR candidate is missing validated context: {', '.join(missing)}."],
    )


def _mark_promoted(finding: Finding, reasons: list[str]) -> Finding:
    if not any(item.source == "NOPE evidence gate" for item in finding.evidence):
        finding.evidence.append(
            Evidence(
                source="NOPE evidence gate",
                file=finding.affected_file,
                line=finding.start_line,
                end_line=finding.end_line,
                message="Promoted after context validation: " + " ".join(reasons),
            )
        )
    finding.verification_state = "context_validated"
    return finding


def _load_context(
    finding: Finding, root: Path | None, cache: dict[str, FileContext]
) -> FileContext:
    rel = finding.affected_file or _first_evidence_file(finding) or ""
    normalized = rel.replace("\\", "/")
    if normalized in cache:
        return cache[normalized]

    context = FileContext(path=normalized, generated=_is_generated_path(normalized))
    cache[normalized] = context
    if not root or not normalized:
        return context

    candidate = (root / normalized).resolve()
    try:
        root_resolved = root.resolve()
        if root_resolved not in candidate.parents and candidate != root_resolved:
            return context
        size = candidate.stat().st_size
        context.exists = True
        if size > MAX_CONTEXT_BYTES:
            context.too_large = True
            return context
        context.text = candidate.read_text(encoding="utf-8", errors="ignore")
        context.window = _line_window(
            context.text, finding.start_line or _first_evidence_line(finding)
        )
    except (OSError, ValueError):
        return context
    return context


def _line_window(text: str, line: int | None) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    if not line:
        return "\n".join(lines[: min(len(lines), CONTEXT_RADIUS * 2)])
    start = max(line - CONTEXT_RADIUS - 1, 0)
    end = min(line + CONTEXT_RADIUS, len(lines))
    return "\n".join(lines[start:end])


def _is_generated_path(path: str) -> bool:
    lowered = path.lower().replace("\\", "/")
    parts = set(lowered.split("/"))
    return bool(parts & GENERATED_PARTS) or lowered.endswith(GENERATED_SUFFIXES)


def _is_authorization_like(category: str, title: str, rule_id: str) -> bool:
    haystack = f"{category} {title} {rule_id}"
    return any(
        term in haystack
        for term in ("authorization", "idor", "owner", "tenant", "access control", "authz")
    )


def _first_evidence_file(finding: Finding) -> str | None:
    for evidence in finding.evidence:
        if evidence.file:
            return evidence.file
    return None


def _first_evidence_line(finding: Finding) -> int | None:
    for evidence in finding.evidence:
        if evidence.line:
            return evidence.line
    return None


def _evidence_text(finding: Finding) -> str:
    pieces = [finding.description or ""]
    for evidence in finding.evidence:
        pieces.extend([evidence.message or "", evidence.snippet or ""])
    return "\n".join(pieces)
