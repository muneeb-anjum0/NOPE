from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from nope_api.models import AttackSurfaceItem, Confidence, Evidence, Finding, Scan, Severity, now_utc
from nope_api.rules_engine import canonical_fingerprint, dedupe_findings, load_rules
from nope_api.security import redact


RULES_V2_VERSION = "rules-v2.1"
MAX_RULES_V2_FILE_BYTES = 256 * 1024
MAX_RULES_V2_FILES = 1200
MAX_RULES_V2_CANDIDATES = 2000
TEXT_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".go",
    ".java",
    ".cs",
    ".php",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".env",
    ".json",
    ".toml",
    ".tf",
    ".yaml",
    ".yml",
    ".md",
    ".rules",
    ".svelte",
}
SKIP_DIRS = {".git", ".next", "node_modules", "__pycache__", ".pytest_cache", "dist", "build", "coverage", "target", "vendor"}


DecisionResult = Literal["promoted", "withheld", "rejected", "needs_manual_review", "not_applicable"]


class RuleDefinition(BaseModel):
    rule_id: str
    version: str = "2.0.0"
    title: str
    description: str
    family: str
    category: str
    subcategory: str = "general"
    default_severity: Severity = Severity.medium
    confidence_model: str = "evidence-gated"
    cwe: str | None = None
    owasp: str | None = None
    supported_languages: list[str] = Field(default_factory=list)
    supported_frameworks: list[str] = Field(default_factory=list)
    applicability: list[str] = Field(default_factory=list)
    candidate_sources: list[str] = Field(default_factory=list)
    evidence_requirements: list[str] = Field(default_factory=list)
    correlation_requirements: list[str] = Field(default_factory=list)
    promotion_requirements: list[str] = Field(default_factory=list)
    rejection_conditions: list[str] = Field(default_factory=list)
    safe_patterns: list[str] = Field(default_factory=list)
    false_positive_guidance: str = ""
    remediation: str
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    deprecated: bool = False
    replacement_rule: str | None = None
    benchmark_fixtures: list[str] = Field(default_factory=list)
    test_references: list[str] = Field(default_factory=list)

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        if not re.fullmatch(r"NOPE-[A-Z0-9-]+-\d{3}", value):
            raise ValueError(f"Invalid NOPE rule id: {value}")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not re.fullmatch(r"\d+\.\d+\.\d+", value):
            raise ValueError("Rule version must use semantic versioning.")
        return value


class RuleEvidence(BaseModel):
    kind: str
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    route: str | None = None
    symbol: str | None = None
    source: str
    message: str
    snippet: str | None = None
    strength: Literal["direct_deterministic", "strong_correlated", "corroborated", "inferred", "incomplete", "contradictory"] = "inferred"
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleCandidate(BaseModel):
    candidate_id: str
    rule_id: str
    rule_version: str
    repository: str | None = None
    scan_id: str | None = None
    project_id: str | None = None
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    route: str | None = None
    source_type: str
    evidence: list[RuleEvidence] = Field(default_factory=list)
    preliminary_severity: Severity
    preliminary_confidence: Confidence = Confidence.uncertain
    missing_evidence: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)
    safe_pattern_evidence: list[str] = Field(default_factory=list)
    graph_references: list[str] = Field(default_factory=list)
    scanner_references: list[str] = Field(default_factory=list)
    related_candidates: list[str] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    framework: str | None = None
    family: str
    confidence_factors: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: now_utc().isoformat())


class PromotionDecision(BaseModel):
    candidate_id: str
    rule_id: str
    rule_version: str
    result: DecisionResult
    evidence_used: list[RuleEvidence] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)
    confidence: Confidence
    evidence_strength: str
    reason: str
    machine_reason: str
    correlation_path: list[str] = Field(default_factory=list)
    suggested_manual_verification: str | None = None
    created_at: str = Field(default_factory=lambda: now_utc().isoformat())


@dataclass
class RepositoryFile:
    rel: str
    text: str
    line_offsets: list[int] = field(default_factory=list)


def _rule(
    rule_id: str,
    title: str,
    family: str,
    category: str,
    *,
    subcategory: str = "general",
    severity: Severity = Severity.medium,
    cwe: str | None = None,
    owasp: str | None = None,
    frameworks: list[str] | None = None,
    requirements: list[str] | None = None,
    safe: list[str] | None = None,
    remediation: str | None = None,
    tags: list[str] | None = None,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        title=title,
        description=title,
        family=family,
        category=category,
        subcategory=subcategory,
        default_severity=severity,
        cwe=cwe,
        owasp=owasp,
        supported_frameworks=frameworks or [],
        candidate_sources=["repository", "attack_surface", "code_graph", "scanner_evidence"],
        evidence_requirements=requirements or ["deterministic source evidence", "bounded context"],
        correlation_requirements=["same-file or graph-correlated evidence where applicable"],
        promotion_requirements=["required evidence present", "no safe-pattern contradiction"],
        rejection_conditions=["safe pattern proves equivalent protection", "candidate not applicable to framework"],
        safe_patterns=safe or ["centralized authorization wrapper", "validated DTO serializer", "allowlisted redirect helper", "bounded rate-limit middleware"],
        false_positive_guidance="Review the evidence path, safe-pattern evidence, and missing-evidence list before accepting or dismissing.",
        remediation=remediation or "Apply the relevant server-side control and rerun NOPE.",
        tags=tags or [],
    )


def _catalog_rules() -> list[RuleDefinition]:
    rules: list[RuleDefinition] = []
    try:
        for legacy in load_rules():
            rules.append(
                _rule(
                    str(legacy["id"]),
                    str(legacy["title"]),
                    "legacy-upgraded",
                    str(legacy["category"]),
                    severity=Severity(str(legacy["severity"])),
                    cwe=legacy.get("cwe"),
                    owasp=legacy.get("owasp"),
                    requirements=["legacy pattern match", "context validation", "promotion gate"],
                    remediation=str(legacy.get("remediation") or "Review and fix the matched code."),
                    tags=["existing-nope-rule", "rules-v2-upgraded"],
                )
            )
    except Exception:
        rules = []

    additions = [
        ("NOPE-NEXT-AUTHZ-001", "Server Action mutates data without server authentication", "nextjs", "Authorization", Severity.high),
        ("NOPE-NEXT-AUTHZ-002", "Route handler accesses data before authentication or session validation", "nextjs", "Authorization", Severity.high),
        ("NOPE-NEXT-AUTHZ-003", "Middleware-only protection is treated as sufficient authorization", "nextjs", "Authorization", Severity.medium),
        ("NOPE-NEXT-AUTHZ-004", "Logged-in check exists but resource ownership or tenant authorization is missing", "nextjs", "Authorization", Severity.high),
        ("NOPE-NEXT-AUTHZ-005", "Admin route is protected only by frontend rendering or navigation conditions", "nextjs", "Authorization", Severity.high),
        ("NOPE-NEXT-AUTHZ-006", "API route trusts user, role, tenant, organization, workspace, or team ID from request input", "nextjs", "Authorization", Severity.high),
        ("NOPE-NEXT-DATA-001", "Secret-like value is exposed through NEXT_PUBLIC", "nextjs", "Secrets", Severity.high),
        ("NOPE-NEXT-DATA-002", "Server component passes sensitive data into a client component", "nextjs", "Privacy", Severity.high),
        ("NOPE-NEXT-DATA-003", "Route returns a full ORM model or user object instead of an allowlisted DTO", "nextjs", "Privacy", Severity.medium),
        ("NOPE-NEXT-DATA-004", "User-specific or tenant-specific data uses public or shared static caching", "nextjs", "Privacy", Severity.high),
        ("NOPE-NEXT-DATA-005", "ISR or static generation is used for private user-specific or tenant-specific pages", "nextjs", "Privacy", Severity.high),
        ("NOPE-NEXT-DATA-006", "Cookies, session, or authenticated data is mixed with unsafe shared caching", "nextjs", "Privacy", Severity.high),
        ("NOPE-NEXT-REDIRECT-001", "User-controlled redirect target reaches redirect without allowlisting", "nextjs", "URL scope", Severity.medium),
        ("NOPE-NEXT-ERROR-001", "Error handler may leak stack, environment, or internal path details", "nextjs", "Privacy", Severity.medium),
        ("NOPE-NEXT-UPLOAD-001", "Upload route lacks size, type, filename, or path controls", "nextjs", "Injection", Severity.high),
        ("NOPE-PRISMA-001", "Prisma findUnique or findFirst uses user-controlled ID without owner or tenant predicate", "prisma", "Authorization", Severity.high),
        ("NOPE-PRISMA-002", "Prisma update, delete, or upsert by ID lacks owner or tenant predicate", "prisma", "Authorization", Severity.critical),
        ("NOPE-PRISMA-003", "Sensitive relation is included without authorization proof", "prisma", "Privacy", Severity.high),
        ("NOPE-PRISMA-004", "Sensitive fields are selected or returned", "prisma", "Privacy", Severity.high),
        ("NOPE-PRISMA-005", "Multi-tenant model query lacks organization, workspace, or team predicate", "prisma", "Authorization", Severity.high),
        ("NOPE-PRISMA-006", "Raw SQL uses user input", "prisma", "Injection", Severity.critical),
        ("NOPE-PRISMA-007", "Authorization check and mutation are separated without transaction safety", "prisma", "Authorization", Severity.medium),
        ("NOPE-PRISMA-008", "findMany on tenant-owned model lacks tenant filter", "prisma", "Authorization", Severity.high),
        ("NOPE-PRISMA-009", "Pagination or search endpoint may leak records across tenant", "prisma", "Authorization", Severity.high),
        ("NOPE-PRISMA-010", "Soft-delete or private records are queried without visibility predicate", "prisma", "Authorization", Severity.medium),
        ("NOPE-SUPABASE-RLS-001", "App queries a table with no matching RLS policy", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-002", "RLS policy allows all authenticated users without owner or tenant predicate", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-003", "Insert or update policy is missing WITH CHECK ownership constraint", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-004", "Delete policy is broader than read or update policy", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-005", "auth.uid is compared to the wrong or nullable column", "supabase", "Supabase", Severity.medium),
        ("NOPE-SUPABASE-RLS-006", "Public bucket is used for private user data", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-007", "Signed URL expiry is missing or too long", "supabase", "Supabase", Severity.medium),
        ("NOPE-SUPABASE-RLS-008", "Anon key reads sensitive table without restrictive RLS", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-009", "RPC or function may bypass RLS or use security definer unsafely", "supabase", "Supabase", Severity.high),
        ("NOPE-SUPABASE-RLS-010", "Storage path policy lacks user or tenant prefix binding", "supabase", "Supabase", Severity.high),
        ("NOPE-AUTH-CLERK-001", "Clerk user ID is not used in DB or storage predicate", "auth-provider", "Authorization", Severity.high),
        ("NOPE-AUTH-CLERK-002", "Clerk organization ID is ignored in tenant query", "auth-provider", "Authorization", Severity.high),
        ("NOPE-AUTH-CLERK-003", "Clerk metadata role is trusted without server verification", "auth-provider", "Authorization", Severity.medium),
        ("NOPE-AUTH-AUTHJS-001", "Auth.js session exists but role or tenant checks are missing", "auth-provider", "Authorization", Severity.high),
        ("NOPE-AUTH-AUTHJS-002", "Sensitive token is stored in client-readable Auth.js session", "auth-provider", "Privacy", Severity.high),
        ("NOPE-AUTH-AUTHJS-003", "Credentials provider lacks brute-force or rate-limit controls", "auth-provider", "Authentication", Severity.high),
        ("NOPE-AUTH-SUPABASE-001", "Supabase user is checked but not used in query filters", "auth-provider", "Authorization", Severity.high),
        ("NOPE-AUTH-SUPABASE-002", "Supabase client session is trusted without server verification", "auth-provider", "Authentication", Severity.high),
        ("NOPE-AUTH-SUPABASE-003", "getSession is used where getUser verification is required", "auth-provider", "Authentication", Severity.medium),
        ("NOPE-CORR-IDOR-001", "Route parameter reaches DB lookup without owner or tenant predicate", "correlation", "Authorization", Severity.high),
        ("NOPE-CORR-MUTATION-001", "Route or body ID reaches update or delete without owner or tenant predicate", "correlation", "Authorization", Severity.critical),
        ("NOPE-CORR-RLS-001", "Supabase table usage has missing or weak matching RLS", "correlation", "Supabase", Severity.high),
        ("NOPE-CORR-STORAGE-001", "Private file route or upload is backed by public storage", "correlation", "Supabase", Severity.high),
        ("NOPE-CORR-SECRET-001", "Secret source reaches client bundle or public artifact", "correlation", "Secrets", Severity.critical),
        ("NOPE-CORR-CACHE-001", "Authenticated data path uses public or static cache", "correlation", "Privacy", Severity.high),
        ("NOPE-CORR-AI-001", "Public route reaches AI call without auth, rate, or token controls", "correlation", "AI abuse", Severity.high),
        ("NOPE-CORR-EXPORT-001", "Export or report route uses user-controlled query without ownership predicate", "correlation", "Authorization", Severity.high),
        ("NOPE-CORR-WEBHOOK-001", "Webhook route mutates state without signature verification", "correlation", "Authentication", Severity.high),
        ("NOPE-CORR-ADMIN-001", "Admin route relies on frontend-only role protection", "correlation", "Authorization", Severity.high),
        ("NOPE-CORR-LOG-001", "Sensitive data source reaches logger, error, or report output", "correlation", "Privacy", Severity.high),
        ("NOPE-CORR-REDIRECT-001", "User-controlled redirect value reaches response redirect", "correlation", "URL scope", Severity.medium),
        ("NOPE-CORR-UPLOAD-001", "Upload filename or path reaches public or executable storage", "correlation", "Injection", Severity.high),
        ("NOPE-CORR-SEARCH-001", "Search or filter endpoint may expose tenant data", "correlation", "Authorization", Severity.high),
        ("NOPE-CORR-QUEUE-001", "Background job uses user-controlled target without scope check", "correlation", "Authorization", Severity.high),
        ("NOPE-AI-COST-002", "AI endpoint lacks per-user request budget", "ai-cost", "AI abuse", Severity.medium),
        ("NOPE-AI-COST-003", "AI endpoint lacks max token, output, or streaming limits", "ai-cost", "AI abuse", Severity.high),
        ("NOPE-AI-COST-004", "Tool or function calling lacks explicit allowlist", "ai-cost", "AI abuse", Severity.high),
        ("NOPE-AI-COST-005", "Prompts or responses are logged with secrets or PII", "ai-cost", "Privacy", Severity.high),
        ("NOPE-AI-COST-006", "File or chat upload sent to AI lacks size or content limits", "ai-cost", "AI abuse", Severity.medium),
        ("NOPE-AI-COST-007", "Public AI route allows unauthenticated generation", "ai-cost", "AI abuse", Severity.high),
        ("NOPE-AI-COST-008", "User-controlled system or developer prompt path exists", "ai-cost", "AI abuse", Severity.high),
        ("NOPE-AI-COST-009", "RAG retrieves untrusted repo instructions without boundary labels", "ai-cost", "AI abuse", Severity.medium),
        ("NOPE-AI-COST-010", "AI retry loop lacks timeout, backoff, or cancellation controls", "ai-cost", "AI abuse", Severity.medium),
        ("NOPE-WEBHOOK-001", "Webhook missing signature verification", "webhook-oauth", "Authentication", Severity.high),
        ("NOPE-WEBHOOK-002", "Webhook verifies signature after raw body was changed", "webhook-oauth", "Authentication", Severity.high),
        ("NOPE-WEBHOOK-003", "Webhook replay protection is missing", "webhook-oauth", "Authentication", Severity.medium),
        ("NOPE-WEBHOOK-004", "Webhook mutation is not idempotent", "webhook-oauth", "Authentication", Severity.medium),
        ("NOPE-OAUTH-001", "OAuth callback missing state validation", "webhook-oauth", "Authentication", Severity.high),
        ("NOPE-OAUTH-002", "OAuth return URL is not allowlisted", "webhook-oauth", "URL scope", Severity.high),
        ("NOPE-OAUTH-003", "OAuth access or refresh token is stored client-side", "webhook-oauth", "Privacy", Severity.high),
        ("NOPE-OAUTH-004", "OAuth token is logged or returned in response", "webhook-oauth", "Privacy", Severity.high),
        ("NOPE-OAUTH-005", "OAuth callback accepts provider or account mismatch", "webhook-oauth", "Authentication", Severity.high),
        ("NOPE-RATE-002", "Expensive unauthenticated route lacks rate limit", "rate-limit", "Rate limiting", Severity.high),
        ("NOPE-RATE-003", "Upload, export, or report route lacks quota", "rate-limit", "Rate limiting", Severity.medium),
        ("NOPE-RATE-004", "Password reset, signup, or OTP lacks identity and IP throttles", "rate-limit", "Rate limiting", Severity.high),
        ("NOPE-RATE-005", "Search or scrape endpoint lacks pagination and limit caps", "rate-limit", "Rate limiting", Severity.medium),
        ("NOPE-RATE-006", "PDF or report generation lacks job quota", "rate-limit", "Rate limiting", Severity.medium),
        ("NOPE-RATE-007", "Email or SMS endpoint lacks abuse controls", "rate-limit", "Rate limiting", Severity.high),
        ("NOPE-RATE-008", "GraphQL endpoint lacks depth, complexity, or rate controls", "rate-limit", "Rate limiting", Severity.high),
        ("NOPE-PRIVACY-002", "Tracker loads before consent", "privacy", "Privacy", Severity.medium),
        ("NOPE-PRIVACY-003", "PII is sent to third-party script or AI without boundary", "privacy", "Privacy", Severity.high),
        ("NOPE-PRIVACY-004", "Logs include email, phone, token, reset, or payment info", "privacy", "Privacy", Severity.high),
        ("NOPE-PRIVACY-005", "Error response leaks stack, environment, or internal path", "privacy", "Privacy", Severity.medium),
        ("NOPE-PRIVACY-006", "Source maps or build artifacts expose private paths", "privacy", "Privacy", Severity.medium),
        ("NOPE-PRIVACY-007", "Public analytics receives user or session identifiers", "privacy", "Privacy", Severity.medium),
        ("NOPE-PRIVACY-008", "Report or export includes secrets or raw tokens", "privacy", "Privacy", Severity.high),
        ("NOPE-PRIVACY-009", "Debug endpoint leaks config, environment, headers, or DB info", "privacy", "Privacy", Severity.high),
        ("NOPE-UPLOAD-002", "Upload lacks size, MIME, extension, or content checks", "upload-storage", "Injection", Severity.high),
        ("NOPE-UPLOAD-003", "User filename or path reaches storage key", "upload-storage", "Injection", Severity.high),
        ("NOPE-UPLOAD-004", "Uploaded file is served from executable or public path", "upload-storage", "Injection", Severity.high),
        ("NOPE-UPLOAD-005", "Upload allows dangerous archive or file types", "upload-storage", "Injection", Severity.medium),
        ("NOPE-ARCHIVE-002", "Archive extraction lacks symlink, hardlink, depth, count, or bomb controls", "upload-storage", "Injection", Severity.high),
        ("NOPE-ARCHIVE-003", "Archive path normalization misses Unicode or traversal tricks", "upload-storage", "Injection", Severity.high),
        ("NOPE-STORAGE-001", "Download route uses raw user-controlled path or key", "upload-storage", "Injection", Severity.high),
        ("NOPE-STORAGE-002", "Signed URL lacks authorization or expiry guard", "upload-storage", "Supabase", Severity.high),
        ("NOPE-STORAGE-003", "Storage object ACL is broader than route authorization", "upload-storage", "Supabase", Severity.high),
        ("NOPE-STORAGE-004", "Private file identifier is guessable or sequential", "upload-storage", "Privacy", Severity.medium),
        ("NOPE-DEPLOY-001", "Debug or development mode is enabled in production-like config", "deployment-ci", "Staging", Severity.high),
        ("NOPE-DEPLOY-002", "CORS wildcard is combined with credentials", "deployment-ci", "CORS", Severity.high),
        ("NOPE-DEPLOY-003", "CSP is missing or unsafe without justification", "deployment-ci", "Privacy", Severity.medium),
        ("NOPE-DEPLOY-004", "HSTS is missing on production HTTPS config", "deployment-ci", "Privacy", Severity.medium),
        ("NOPE-DEPLOY-005", "Admin, staging, or development route is exposed", "deployment-ci", "Staging", Severity.high),
        ("NOPE-DEPLOY-006", "Container runs as root or with broad capabilities", "deployment-ci", "Containers", Severity.high),
        ("NOPE-DEPLOY-007", "CI exposes secrets to pull requests, forks, or logs", "deployment-ci", "CI/CD", Severity.high),
        ("NOPE-DEPLOY-008", "Database, Redis, MinIO, or admin service is publicly exposed", "deployment-ci", "Staging", Severity.critical),
        ("NOPE-DEPLOY-009", "Container is missing healthcheck or resource limits", "deployment-ci", "Containers", Severity.medium),
        ("NOPE-DEPLOY-010", "Docker socket is mounted into app or worker container", "deployment-ci", "Containers", Severity.critical),
    ]
    existing = {rule.rule_id for rule in rules}
    for rule_id, title, family, category, severity in additions:
        if rule_id in existing:
            continue
        rules.append(
            _rule(
                rule_id,
                title,
                family,
                category,
                severity=severity,
                requirements=["candidate signal", "correlated context", "safe-pattern check"],
                frameworks=[family] if family in {"nextjs", "prisma", "supabase"} else [],
                tags=["rules-v2"],
            )
        )
    return rules


RULE_CATALOG = _catalog_rules()
RULE_BY_ID = {rule.rule_id: rule for rule in RULE_CATALOG}


def validate_rule_catalog(rules: list[RuleDefinition] | None = None) -> dict[str, Any]:
    rules = rules or RULE_CATALOG
    seen: set[str] = set()
    errors: list[str] = []
    for rule in rules:
        try:
            RuleDefinition(**rule.model_dump(mode="json"))
        except ValidationError as exc:
            errors.append(f"{rule.rule_id}: {exc}")
        if rule.rule_id in seen:
            errors.append(f"Duplicate rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
    if errors:
        raise ValueError("; ".join(errors))
    by_family: dict[str, int] = {}
    for rule in rules:
        by_family[rule.family] = by_family.get(rule.family, 0) + 1
    return {"version": RULES_V2_VERSION, "rule_count": len(rules), "families": by_family}


def _stable_id(*parts: object, prefix: str = "cand") -> str:
    digest = hashlib.sha256(":".join(str(part or "") for part in parts).encode("utf-8", errors="ignore")).hexdigest()
    return f"{prefix}_{digest[:20]}"


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return redact(lines[line - 1].strip())[:500]
    return ""


def _iter_repository_files(root: Path | None) -> list[RepositoryFile]:
    if not root or not root.exists():
        return []
    files: list[RepositoryFile] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if len(files) >= MAX_RULES_V2_FILES:
            break
        if not path.is_file():
            continue
        rel_parts = set(path.relative_to(root).parts)
        if rel_parts & SKIP_DIRS:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name.lower() not in {"dockerfile", ".env"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:MAX_RULES_V2_FILE_BYTES]
        except OSError:
            continue
        files.append(RepositoryFile(rel=path.relative_to(root).as_posix(), text=text))
    return files


AUTH_RE = re.compile(r"\b(auth\(|getServerSession|requireUser|requireAuth|currentUser|getUser|getSession|withAuth|locals\.user|session\.user|auth\.uid)\b", re.I)
OWNER_RE = re.compile(r"\b(ownerId|owner_id|tenantId|tenant_id|orgId|organizationId|workspaceId|teamId|userId|user_id|createdBy|accountId)\b", re.I)
DB_READ_RE = re.compile(r"\b(prisma\.\w+\.(findUnique|findFirst|findMany)|supabase\.from\(|\.select\(|db\.query|sql`|SELECT\s)", re.I)
DB_MUTATION_RE = re.compile(r"\b(prisma\.\w+\.(update|delete|upsert|create)|\.insert\(|\.update\(|\.delete\(|UPDATE\s|DELETE\s|INSERT\s)", re.I)
INPUT_ID_RE = re.compile(r"\b(params\.\w*id|searchParams\.get\(['\"][^'\"]*id|req\.(query|body|params)|request\.json\(|body\.(id|userId|tenantId|role|orgId)|query\.(id|userId|tenantId)|callbackUrl|returnTo|next)\b", re.I)
CLIENT_TRUST_RE = re.compile(r"\b(localStorage|sessionStorage|document\.cookie|body\.(role|tenantId|orgId|isAdmin|userId)|query\.(role|tenantId|orgId|isAdmin|userId))\b", re.I)
SECRET_RE = re.compile(r"\b(NEXT_PUBLIC_[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)|sk-[A-Za-z0-9_-]{12,}|service_role|SUPABASE_SERVICE_ROLE|PRIVATE_KEY)\b", re.I)
CACHE_RE = re.compile(r"\b(revalidate\s*=\s*\d+|dynamic\s*=\s*['\"]force-static|cache\s*:\s*['\"]force-cache|unstable_cache|public,\s*max-age)\b", re.I)
AI_RE = re.compile(r"\b(openai|anthropic|gemini|llama|chat\.completions|responses\.create|generateText|streamText|tool_choice|function_call)\b", re.I)
RATE_RE = re.compile(r"\b(rateLimit|rate_limit|throttle|quota|budget|limitPer|redis.*incr|upstash)\b", re.I)
TOKEN_LIMIT_RE = re.compile(r"\b(max_tokens|maxOutputTokens|n_predict|timeout|AbortController|stream\s*:\s*false)\b", re.I)
WEBHOOK_RE = re.compile(r"\b(webhook|stripe|svix|github\.webhook|clerk)\b", re.I)
SIGNATURE_RE = re.compile(r"\b(signature|constructEvent|verify|svix-id|svix-signature|x-hub-signature|stripe-signature)\b", re.I)
REDIRECT_RE = re.compile(r"\b(redirect\(|NextResponse\.redirect|res\.redirect|callbackUrl|returnTo|next=|redirect_uri)\b", re.I)
UPLOAD_RE = re.compile(r"\b(formData\(|multer|busboy|file\.name|filename|writeFile|putObject|upload|createSignedUploadUrl)\b", re.I)
UPLOAD_GUARD_RE = re.compile(r"\b(file\.size|content-type|mime|extension|allowedTypes|zod|schema|maxSize|sanitize|basename|normalize)\b", re.I)
LOG_RE = re.compile(r"\b(console\.log|logger\.(info|debug|error|warn)|print\(|logging\.)\b", re.I)
HEADER_RE = re.compile(r"\b(Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|Referrer-Policy|Permissions-Policy|nosniff)\b", re.I)
DOCKER_RISK_RE = re.compile(r"\b(USER\s+root|privileged:\s*true|/var/run/docker\.sock|network_mode:\s*host|cap_add|--privileged)\b", re.I)
DOCKER_SAFE_RE = re.compile(r"\b(USER\s+(?!root)\w+|no-new-privileges|cap_drop|read_only|HEALTHCHECK|memory|cpus)\b", re.I)
RLS_POLICY_RE = re.compile(r"\b(create\s+policy|alter\s+table.*enable\s+row\s+level\s+security|with\s+check|auth\.uid\(\)|security\s+definer|storage\.objects)\b", re.I | re.S)
PUBLIC_POLICY_RE = re.compile(r"\b(using\s*\(\s*true\s*\)|to\s+authenticated|public\s*[:=]\s*true|allow\s+read\s*:\s*if\s+true)\b", re.I)


def _candidate(
    rule_id: str,
    scan: Scan,
    *,
    source_type: str,
    file: str | None = None,
    line: int | None = None,
    route: str | None = None,
    symbol: str | None = None,
    evidence: list[RuleEvidence] | None = None,
    missing: list[str] | None = None,
    contradictory: list[str] | None = None,
    safe: list[str] | None = None,
    graph_refs: list[str] | None = None,
    scanner_refs: list[str] | None = None,
    related_findings: list[str] | None = None,
    framework: str | None = None,
    confidence: Confidence = Confidence.uncertain,
    resources: list[str] | None = None,
) -> RuleCandidate:
    rule = RULE_BY_ID[rule_id]
    return RuleCandidate(
        candidate_id=_stable_id(scan.id, rule_id, file, line, route, source_type),
        rule_id=rule_id,
        rule_version=rule.version,
        repository=scan.repository_name,
        scan_id=scan.id,
        project_id=scan.project_id,
        file=file,
        line=line,
        end_line=line,
        symbol=symbol,
        route=route,
        source_type=source_type,
        evidence=evidence or [],
        preliminary_severity=rule.default_severity,
        preliminary_confidence=confidence,
        missing_evidence=missing or [],
        contradictory_evidence=contradictory or [],
        safe_pattern_evidence=safe or [],
        graph_references=graph_refs or [],
        scanner_references=scanner_refs or [],
        related_findings=related_findings or [],
        affected_resources=resources or [],
        framework=framework,
        family=rule.family,
        confidence_factors={"evidence_count": len(evidence or []), "missing_count": len(missing or []), "safe_pattern_count": len(safe or [])},
    )


def _evidence(kind: str, source: str, message: str, *, file: str | None = None, line: int | None = None, route: str | None = None, snippet: str | None = None, strength: str = "inferred", metadata: dict[str, Any] | None = None) -> RuleEvidence:
    return RuleEvidence(kind=kind, source=source, file=file, line=line, end_line=line, route=route, message=message, snippet=redact(snippet or "")[:500] or None, strength=strength, metadata=metadata or {})


def _has_safe_auth(text: str) -> bool:
    return bool(AUTH_RE.search(text) and OWNER_RE.search(text))


def _file_candidates(scan: Scan, files: list[RepositoryFile]) -> list[RuleCandidate]:
    candidates: list[RuleCandidate] = []
    for repo_file in files:
        text = repo_file.text
        lower_rel = repo_file.rel.lower()
        is_route = any(token in lower_rel for token in ("app/api/", "pages/api/", "src/routes/", "route.", "+server.", "server/action"))
        is_client = "'use client'" in text[:200].lower() or '"use client"' in text[:200].lower() or lower_rel.endswith((".tsx", ".jsx", ".svelte"))
        has_auth = bool(AUTH_RE.search(text))
        has_owner = bool(OWNER_RE.search(text))
        has_db_read = bool(DB_READ_RE.search(text))
        has_db_mutation = bool(DB_MUTATION_RE.search(text))
        has_input_id = bool(INPUT_ID_RE.search(text))
        safe_auth = _has_safe_auth(text)

        for match in SECRET_RE.finditer(text):
            line = _line_for_offset(text, match.start())
            if "NEXT_PUBLIC" in match.group(0).upper():
                candidates.append(_candidate("NOPE-NEXT-DATA-001", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.high, evidence=[_evidence("env", "Rules v2", "Secret-like public environment variable.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="direct_deterministic")]))
            if is_client or "public" in lower_rel or ".map" in lower_rel:
                candidates.append(_candidate("NOPE-CORR-SECRET-001", scan, source_type="repository", file=repo_file.rel, line=line, confidence=Confidence.high, evidence=[_evidence("secret_flow", "Rules v2", "Secret-like value appears in a client/public path.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))

        if is_route and has_db_read and not has_auth:
            line = _line_for_offset(text, DB_READ_RE.search(text).start()) if DB_READ_RE.search(text) else 1
            candidates.append(_candidate("NOPE-NEXT-AUTHZ-002", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.medium, missing=["authentication/session validation before data access"], evidence=[_evidence("data_access", "Rules v2", "Route handler data access appears before auth/session evidence.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if is_route and has_db_read and has_auth and not has_owner:
            line = _line_for_offset(text, DB_READ_RE.search(text).start()) if DB_READ_RE.search(text) else 1
            candidates.append(_candidate("NOPE-NEXT-AUTHZ-004", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.medium, missing=["owner/tenant predicate"], evidence=[_evidence("auth_without_scope", "Rules v2", "Authentication evidence exists, but owner/tenant scope evidence is missing near data access.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if "server action" in text.lower() and has_db_mutation and not has_auth:
            line = _line_for_offset(text, DB_MUTATION_RE.search(text).start()) if DB_MUTATION_RE.search(text) else 1
            candidates.append(_candidate("NOPE-NEXT-AUTHZ-001", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.medium, missing=["server-side auth check"], evidence=[_evidence("server_action_mutation", "Rules v2", "Server Action mutation lacks nearby auth evidence.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if CLIENT_TRUST_RE.search(text) and (has_db_read or has_db_mutation or is_route):
            line = _line_for_offset(text, CLIENT_TRUST_RE.search(text).start())
            candidates.append(_candidate("NOPE-NEXT-AUTHZ-006", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.high, evidence=[_evidence("client_authority", "Rules v2", "Server-side path references role/user/tenant authority from request or browser-controlled input.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="direct_deterministic")]))
        if has_db_read and has_input_id:
            line = _line_for_offset(text, DB_READ_RE.search(text).start()) if DB_READ_RE.search(text) else 1
            candidates.append(_candidate("NOPE-PRISMA-001" if "prisma" in text.lower() else "NOPE-CORR-IDOR-001", scan, source_type="repository", file=repo_file.rel, line=line, route=None, framework="prisma" if "prisma" in text.lower() else None, confidence=Confidence.high if not safe_auth else Confidence.low, missing=[] if safe_auth else ["owner/tenant predicate"], safe=["Auth and owner/tenant signal in same file."] if safe_auth else [], evidence=[_evidence("source_to_sink", "Rules v2", "User-controlled ID and database lookup are present in bounded context.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if has_db_mutation and has_input_id:
            line = _line_for_offset(text, DB_MUTATION_RE.search(text).start()) if DB_MUTATION_RE.search(text) else 1
            candidates.append(_candidate("NOPE-PRISMA-002" if "prisma" in text.lower() else "NOPE-CORR-MUTATION-001", scan, source_type="repository", file=repo_file.rel, line=line, framework="prisma" if "prisma" in text.lower() else None, confidence=Confidence.high if not safe_auth else Confidence.low, missing=[] if safe_auth else ["owner/tenant predicate"], safe=["Auth and owner/tenant signal in same file."] if safe_auth else [], evidence=[_evidence("mutation_sink", "Rules v2", "User-controlled ID and mutation sink are present in bounded context.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if "include:" in text and re.search(r"\b(password|token|secret|sessions?|apiKeys?|reset)\b", text, re.I):
            line = _line_for_offset(text, text.lower().find("include:"))
            candidates.append(_candidate("NOPE-PRISMA-003", scan, source_type="repository", file=repo_file.rel, line=line, framework="prisma", confidence=Confidence.medium, missing=["authorization proof for sensitive relation"], evidence=[_evidence("sensitive_relation", "Rules v2", "Sensitive relation appears in ORM include block.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="inferred")]))
        if re.search(r"\b(passwordHash|resetToken|refreshToken|accessToken|secret|apiKey)\b", text):
            line = _line_for_offset(text, re.search(r"\b(passwordHash|resetToken|refreshToken|accessToken|secret|apiKey)\b", text).start())
            candidates.append(_candidate("NOPE-PRISMA-004", scan, source_type="repository", file=repo_file.rel, line=line, framework="prisma" if "prisma" in text.lower() else None, confidence=Confidence.medium, missing=["DTO allowlist or redaction proof"], evidence=[_evidence("sensitive_field", "Rules v2", "Sensitive field appears in selected or returned data context.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="inferred")]))

        if "supabase" in text.lower() and ".from(" in text and not RLS_POLICY_RE.search(text):
            line = _line_for_offset(text, text.lower().find(".from("))
            candidates.append(_candidate("NOPE-SUPABASE-RLS-008", scan, source_type="repository", file=repo_file.rel, line=line, framework="supabase", confidence=Confidence.medium, missing=["matching restrictive RLS policy evidence"], evidence=[_evidence("supabase_table_use", "Rules v2", "Supabase table access was found without local RLS policy evidence in the same bounded context.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="inferred")]))
        if PUBLIC_POLICY_RE.search(text):
            line = _line_for_offset(text, PUBLIC_POLICY_RE.search(text).start())
            rule_id = "NOPE-SUPABASE-RLS-002" if "policy" in text.lower() or "auth" in text.lower() else "NOPE-SUPABASE-RLS-006"
            candidates.append(_candidate(rule_id, scan, source_type="repository", file=repo_file.rel, line=line, framework="supabase", confidence=Confidence.high, missing=["data sensitivity proof"] if rule_id.endswith("006") else [], evidence=[_evidence("broad_policy", "Rules v2", "Broad public/authenticated access policy signal was found.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="direct_deterministic")]))
        if "create policy" in text.lower() and "insert" in text.lower() and "with check" not in text.lower():
            line = _line_for_offset(text, text.lower().find("create policy"))
            candidates.append(_candidate("NOPE-SUPABASE-RLS-003", scan, source_type="repository", file=repo_file.rel, line=line, framework="supabase", confidence=Confidence.high, missing=["WITH CHECK ownership predicate"], evidence=[_evidence("rls_policy", "Rules v2", "Insert/update policy lacks WITH CHECK in bounded SQL context.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="direct_deterministic")]))

        if CACHE_RE.search(text) and (has_auth or re.search(r"\b(user|tenant|invoice|account|session|cookies\(\))\b", text, re.I)):
            line = _line_for_offset(text, CACHE_RE.search(text).start())
            candidates.append(_candidate("NOPE-CORR-CACHE-001", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.high, missing=["user-aware cache key or no-store proof"], evidence=[_evidence("cache", "Rules v2", "Authenticated or user-specific context is mixed with static/shared caching.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if REDIRECT_RE.search(text) and re.search(r"\b(searchParams|query|body|callbackUrl|returnTo|next)\b", text, re.I) and not re.search(r"\b(allowlist|allowedRedirect|safeRedirect|sameOrigin|new URL\()", text):
            line = _line_for_offset(text, REDIRECT_RE.search(text).start())
            candidates.append(_candidate("NOPE-NEXT-REDIRECT-001", scan, source_type="repository", file=repo_file.rel, line=line, framework="nextjs", confidence=Confidence.medium, missing=["redirect allowlist"], evidence=[_evidence("redirect", "Rules v2", "User-controlled redirect signal reaches redirect context without allowlist evidence.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="inferred")]))
        if AI_RE.search(text):
            line = _line_for_offset(text, AI_RE.search(text).start())
            missing = []
            if not has_auth:
                missing.append("authentication")
            if not RATE_RE.search(text):
                missing.append("rate limit or per-user budget")
            if not TOKEN_LIMIT_RE.search(text):
                missing.append("token/output/timeout cap")
            rule_id = "NOPE-CORR-AI-001" if missing else "NOPE-AI-COST-004" if "tool" in text.lower() and "allow" not in text.lower() else "NOPE-AI-COST-003"
            candidates.append(_candidate(rule_id, scan, source_type="repository", file=repo_file.rel, line=line, framework=None, confidence=Confidence.medium if missing else Confidence.low, missing=missing, evidence=[_evidence("ai_call", "Rules v2", "AI invocation found; controls were checked in bounded context.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated" if missing else "inferred")]))
        if WEBHOOK_RE.search(text) and (has_db_mutation or "insert" in text.lower() or "update" in text.lower()) and not SIGNATURE_RE.search(text):
            line = _line_for_offset(text, WEBHOOK_RE.search(text).start())
            candidates.append(_candidate("NOPE-WEBHOOK-001", scan, source_type="repository", file=repo_file.rel, line=line, confidence=Confidence.high, missing=["signature verification"], evidence=[_evidence("webhook", "Rules v2", "Webhook-like route mutates state without nearby signature verification evidence.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="strong_correlated")]))
        if UPLOAD_RE.search(text):
            line = _line_for_offset(text, UPLOAD_RE.search(text).start())
            missing = []
            if not UPLOAD_GUARD_RE.search(text):
                missing.append("size/MIME/extension/path validation")
            if re.search(r"\b(file\.name|filename|path\.join|writeFile)\b", text, re.I) and not re.search(r"\b(sanitize|basename|normalize|randomUUID|uuid)\b", text, re.I):
                missing.append("safe storage key generation")
            if missing:
                candidates.append(_candidate("NOPE-UPLOAD-002", scan, source_type="repository", file=repo_file.rel, line=line, confidence=Confidence.medium, missing=missing, evidence=[_evidence("upload", "Rules v2", "Upload handling lacks complete validation evidence.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="inferred")]))
        if LOG_RE.search(text) and re.search(r"\b(password|token|secret|authorization|email|phone|ssn|payment)\b", text, re.I):
            line = _line_for_offset(text, LOG_RE.search(text).start())
            candidates.append(_candidate("NOPE-CORR-LOG-001", scan, source_type="repository", file=repo_file.rel, line=line, confidence=Confidence.medium, evidence=[_evidence("logging", "Rules v2", "Logger/error output is near sensitive data tokens.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="inferred")]))
        if DOCKER_RISK_RE.search(text):
            line = _line_for_offset(text, DOCKER_RISK_RE.search(text).start())
            candidates.append(_candidate("NOPE-DEPLOY-010" if "docker.sock" in text.lower() else "NOPE-DEPLOY-006", scan, source_type="repository", file=repo_file.rel, line=line, confidence=Confidence.high, safe=["Docker hardening signal present."] if DOCKER_SAFE_RE.search(text) else [], missing=[] if DOCKER_SAFE_RE.search(text) else ["final runtime user or hardening proof"], evidence=[_evidence("deployment", "Rules v2", "Container privilege or Docker socket risk signal found.", file=repo_file.rel, line=line, snippet=_line_text(text, line), strength="direct_deterministic")]))
        if "security headers" in text.lower() and not HEADER_RE.search(text):
            candidates.append(_candidate("NOPE-DEPLOY-003", scan, source_type="repository", file=repo_file.rel, line=1, confidence=Confidence.low, missing=["specific security header configuration"], evidence=[_evidence("headers", "Rules v2", "Security-header code path lacks concrete header names.", file=repo_file.rel, line=1, snippet=_line_text(text, 1), strength="incomplete")]))

    return candidates


def _surface_candidates(scan: Scan) -> list[RuleCandidate]:
    candidates: list[RuleCandidate] = []
    for item in scan.attack_surface:
        if item.database_access and item.authorization != "present":
            rule_id = "NOPE-CORR-MUTATION-001" if item.side_effects else "NOPE-CORR-IDOR-001"
            candidates.append(
                _candidate(
                    rule_id,
                    scan,
                    source_type="attack_surface",
                    file=item.file,
                    route=item.route,
                    confidence=Confidence.medium,
                    missing=["owner/tenant authorization proof"],
                    graph_refs=[f"route:{item.method}:{item.route}", f"file:{item.file}"],
                    resources=item.database_access,
                    evidence=[
                        _evidence(
                            "attack_surface",
                            "Rules v2",
                            "Attack surface maps route to database access without authorization signal.",
                            file=item.file,
                            route=item.route,
                            strength="strong_correlated",
                            metadata=item.model_dump(mode="json"),
                        )
                    ],
                )
            )
        if item.external_calls and "ai" in " ".join(item.external_calls + item.side_effects).lower() and item.rate_limiting != "present":
            candidates.append(
                _candidate(
                    "NOPE-CORR-AI-001",
                    scan,
                    source_type="attack_surface",
                    file=item.file,
                    route=item.route,
                    confidence=Confidence.medium,
                    missing=["rate limiting"],
                    evidence=[_evidence("attack_surface", "Rules v2", "Route has external/AI-style call without rate-limit signal.", file=item.file, route=item.route, strength="inferred")],
                )
            )
    return candidates


def _scanner_candidates(scan: Scan, findings: list[Finding]) -> list[RuleCandidate]:
    candidates: list[RuleCandidate] = []
    for finding in findings:
        source = finding.scanner or (finding.scanner_sources[0] if finding.scanner_sources else "")
        if source == "NOPE rules":
            continue
        rule_id = finding.nope_rule_id or finding.original_rule_id or "external"
        candidate_rule = "NOPE-CORR-SECRET-001" if finding.category.lower() == "secrets" else "NOPE-CORR-IDOR-001" if finding.category.lower() == "authorization" else None
        if not candidate_rule:
            continue
        candidates.append(
            _candidate(
                candidate_rule,
                scan,
                source_type="external_scanner",
                file=finding.affected_file,
                line=finding.start_line,
                route=finding.affected_route,
                confidence=finding.confidence,
                scanner_refs=[f"{source}:{rule_id}"],
                related_findings=[finding.id],
                evidence=[
                    _evidence(
                        "scanner_corroboration",
                        source or "external scanner",
                        f"External scanner finding contributes evidence: {finding.title}",
                        file=finding.affected_file,
                        line=finding.start_line,
                        route=finding.affected_route,
                        snippet=finding.evidence[0].snippet if finding.evidence else None,
                        strength="corroborated",
                    )
                ],
            )
        )
    return candidates


def _dedupe_candidates(candidates: list[RuleCandidate]) -> list[RuleCandidate]:
    deduped: dict[str, RuleCandidate] = {}
    for candidate in candidates[:MAX_RULES_V2_CANDIDATES]:
        key = f"{candidate.rule_id}:{candidate.file}:{candidate.line}:{candidate.route}:{candidate.source_type}"
        existing = deduped.get(key)
        if not existing:
            deduped[key] = candidate
            continue
        existing.evidence.extend(candidate.evidence)
        existing.missing_evidence = sorted(set(existing.missing_evidence + candidate.missing_evidence))
        existing.contradictory_evidence = sorted(set(existing.contradictory_evidence + candidate.contradictory_evidence))
        existing.safe_pattern_evidence = sorted(set(existing.safe_pattern_evidence + candidate.safe_pattern_evidence))
        existing.graph_references = sorted(set(existing.graph_references + candidate.graph_references))
        existing.scanner_references = sorted(set(existing.scanner_references + candidate.scanner_references))
        existing.related_findings = sorted(set(existing.related_findings + candidate.related_findings))
        if len(existing.evidence) > 1 and not existing.missing_evidence:
            existing.preliminary_confidence = Confidence.high
    return sorted(deduped.values(), key=lambda item: (item.rule_id, item.file or "", item.line or 0, item.route or ""))


def generate_candidates(scan: Scan, root: Path | None, findings: list[Finding]) -> list[RuleCandidate]:
    started = time.perf_counter()
    files = _iter_repository_files(root)
    candidates = _file_candidates(scan, files)
    candidates.extend(_surface_candidates(scan))
    candidates.extend(_scanner_candidates(scan, findings))
    result = _dedupe_candidates(candidates)
    scan.rules_v2.setdefault("metrics", {})["candidate_generation_ms"] = int((time.perf_counter() - started) * 1000)
    scan.rules_v2.setdefault("metrics", {})["repository_files_considered"] = len(files)
    scan.rules_v2.setdefault("metrics", {})["candidate_truncated"] = len(candidates) > MAX_RULES_V2_CANDIDATES
    return result


def decide_candidate(candidate: RuleCandidate) -> PromotionDecision:
    strengths = {evidence.strength for evidence in candidate.evidence}
    has_direct = bool(strengths & {"direct_deterministic", "strong_correlated", "corroborated"})
    has_missing = bool(candidate.missing_evidence)
    has_safe = bool(candidate.safe_pattern_evidence)
    has_contradiction = bool(candidate.contradictory_evidence)
    if has_contradiction or (has_safe and candidate.preliminary_confidence in {Confidence.low, Confidence.uncertain}):
        return PromotionDecision(
            candidate_id=candidate.candidate_id,
            rule_id=candidate.rule_id,
            rule_version=candidate.rule_version,
            result="rejected",
            evidence_used=candidate.evidence,
            missing_evidence=candidate.missing_evidence,
            contradictory_evidence=candidate.contradictory_evidence + candidate.safe_pattern_evidence,
            confidence=Confidence.low,
            evidence_strength="contradictory",
            reason="Candidate was rejected because safe-pattern or contradictory evidence reduced confidence below promotion threshold.",
            machine_reason="safe_or_contradictory_evidence",
            correlation_path=candidate.graph_references,
        )
    if has_missing:
        return PromotionDecision(
            candidate_id=candidate.candidate_id,
            rule_id=candidate.rule_id,
            rule_version=candidate.rule_version,
            result="withheld" if has_direct else "needs_manual_review",
            evidence_used=candidate.evidence,
            missing_evidence=candidate.missing_evidence,
            contradictory_evidence=candidate.contradictory_evidence,
            confidence=Confidence.medium if has_direct else Confidence.uncertain,
            evidence_strength="incomplete",
            reason="Candidate is suspicious, but required evidence is missing, so it is withheld from confirmed findings.",
            machine_reason="missing_required_evidence",
            correlation_path=candidate.graph_references,
            suggested_manual_verification="Inspect the listed file, route, and related authorization/storage/config helper to confirm whether the missing control exists.",
        )
    if has_direct:
        return PromotionDecision(
            candidate_id=candidate.candidate_id,
            rule_id=candidate.rule_id,
            rule_version=candidate.rule_version,
            result="promoted",
            evidence_used=candidate.evidence,
            confidence=Confidence.high if len(candidate.evidence) > 1 or "corroborated" in strengths else candidate.preliminary_confidence,
            evidence_strength="strong_correlated" if "strong_correlated" in strengths else "direct_deterministic",
            reason="Candidate met promotion requirements with deterministic or strongly correlated evidence and no safe-pattern contradiction.",
            machine_reason="requirements_satisfied",
            correlation_path=candidate.graph_references,
        )
    return PromotionDecision(
        candidate_id=candidate.candidate_id,
        rule_id=candidate.rule_id,
        rule_version=candidate.rule_version,
        result="needs_manual_review",
        evidence_used=candidate.evidence,
        missing_evidence=candidate.missing_evidence or ["strong deterministic evidence"],
        confidence=Confidence.uncertain,
        evidence_strength="inferred",
        reason="Candidate has only inferred evidence and needs manual review.",
        machine_reason="inferred_only",
        correlation_path=candidate.graph_references,
        suggested_manual_verification="Check whether the suspected source reaches the suspected sink and whether an equivalent safe wrapper exists.",
    )


def candidate_to_finding(candidate: RuleCandidate, decision: PromotionDecision) -> Finding:
    rule = RULE_BY_ID[candidate.rule_id]
    evidence = [
        Evidence(
            source=item.source if item.source != "Rules v2" else candidate.rule_id,
            file=item.file,
            line=item.line,
            end_line=item.end_line,
            route=item.route,
            symbol=item.symbol,
            snippet=item.snippet,
            message=item.message,
        )
        for item in decision.evidence_used[:8]
    ]
    evidence.append(
        Evidence(
            source="NOPE Rules v2 promotion gate",
            file=candidate.file,
            line=candidate.line,
            end_line=candidate.end_line,
            route=candidate.route,
            message=f"Promoted by {candidate.rule_id}: {decision.reason}",
        )
    )
    fp_seed = json.dumps(
        {
            "rule": candidate.rule_id,
            "file": candidate.file,
            "line": candidate.line,
            "route": candidate.route,
            "resources": candidate.affected_resources,
        },
        sort_keys=True,
    )
    native_fp = _stable_id(fp_seed, prefix="rv2")
    finding = Finding(
        scan_id=candidate.scan_id,
        project_id=candidate.project_id,
        scanner="NOPE Rules v2",
        original_rule_id=candidate.rule_id,
        nope_rule_id=candidate.rule_id,
        fingerprint=native_fp,
        original_fingerprint=native_fp,
        title=rule.title,
        description=rule.description,
        severity=rule.default_severity,
        original_severity=rule.default_severity.value,
        confidence=decision.confidence,
        original_confidence=decision.confidence.value,
        category=rule.category,
        cwe=rule.cwe,
        owasp=rule.owasp,
        affected_file=candidate.file,
        start_line=candidate.line,
        end_line=candidate.end_line,
        symbol=candidate.symbol,
        affected_route=candidate.route,
        source_metadata={
            "rules_v2": True,
            "rule_version": candidate.rule_version,
            "family": candidate.family,
            "candidate_id": candidate.candidate_id,
            "promotion": decision.model_dump(mode="json"),
            "graph_references": candidate.graph_references,
            "scanner_references": candidate.scanner_references,
        },
        scanner_sources=sorted(set(["NOPE Rules v2"] + [item.source for item in evidence] + candidate.scanner_references)),
        evidence=evidence,
        remediation=rule.remediation,
        test_guidance=f"Add a regression fixture that proves {rule.title.lower()} is blocked and rerun NOPE.",
        fix_available=True,
        verification_state="rules_v2_promoted",
    )
    finding.fingerprint = canonical_fingerprint(finding)
    return finding


def run_rules_v2(scan: Scan, root: Path | None, findings: list[Finding]) -> tuple[list[Finding], dict[str, Any]]:
    validate_rule_catalog()
    started = time.perf_counter()
    candidates = generate_candidates(scan, root, findings)
    decisions = [decide_candidate(candidate) for candidate in candidates]
    promoted_by_id = {decision.candidate_id: decision for decision in decisions if decision.result == "promoted"}
    promoted_findings = [
        candidate_to_finding(candidate, promoted_by_id[candidate.candidate_id])
        for candidate in candidates
        if candidate.candidate_id in promoted_by_id
    ]
    promoted_findings = dedupe_findings(promoted_findings)
    by_result: dict[str, int] = {}
    by_family: dict[str, dict[str, int]] = {}
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    for decision in decisions:
        by_result[decision.result] = by_result.get(decision.result, 0) + 1
        family = candidate_by_id[decision.candidate_id].family
        by_family.setdefault(family, {})
        by_family[family][decision.result] = by_family[family].get(decision.result, 0) + 1
    catalog_summary = validate_rule_catalog()
    payload = {
        "version": RULES_V2_VERSION,
        "catalog": catalog_summary,
        "coverage": {
            "candidate_count": len(candidates),
            "promoted": by_result.get("promoted", 0),
            "withheld": by_result.get("withheld", 0),
            "rejected": by_result.get("rejected", 0),
            "needs_manual_review": by_result.get("needs_manual_review", 0),
            "not_applicable": by_result.get("not_applicable", 0),
            "by_family": by_family,
        },
        "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
        "decisions": [decision.model_dump(mode="json") for decision in decisions],
        "promoted_finding_ids": [finding.id for finding in promoted_findings],
        "metrics": {
            **scan.rules_v2.get("metrics", {}),
            "total_ms": int((time.perf_counter() - started) * 1000),
            "rule_catalog_count": len(RULE_CATALOG),
        },
        "failures": [],
    }
    return promoted_findings, payload


def list_rule_inventory() -> dict[str, Any]:
    summary = validate_rule_catalog()
    return {"summary": summary, "rules": [rule.model_dump(mode="json") for rule in RULE_CATALOG]}
