from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    confirmed = "confirmed"
    high = "high"
    medium = "medium"
    low = "low"
    uncertain = "uncertain"


class FindingStatus(str, Enum):
    new = "new"
    confirmed = "confirmed"
    fixing = "fixing"
    fixed = "fixed"
    verified = "verified"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    suppressed = "suppressed"
    reopened = "reopened"
    reintroduced = "reintroduced"


class BaselineState(str, Enum):
    new = "new"
    existing = "existing"
    fixed = "fixed"
    reintroduced = "reintroduced"


class Suppression(BaseModel):
    reason: str
    user: str
    date: datetime = Field(default_factory=now_utc)
    expiry: datetime | None = None
    scope: str = "finding"


class ScanMode(str, Enum):
    url = "url"
    repository = "repository"
    full = "full"


class CoverageStatus(str, Enum):
    verified = "Verified"
    partial = "Partial"
    not_tested = "Not tested"
    failed = "Failed"
    not_applicable = "Not applicable"


class Project(BaseModel):
    id: str = Field(default_factory=lambda: new_id("prj"))
    name: str
    repository: str | None = None
    target_url: str | None = None
    created_at: datetime = Field(default_factory=now_utc)


class AuthorizationScope(BaseModel):
    confirmed: bool
    confirmed_at: datetime | None = None
    user_identity: str = "local-development-user"
    approved_hosts: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = 60
    allow_private_targets: bool = False
    allow_destructive_testing: bool = False


class StackEvidence(BaseModel):
    technology: str
    category: str
    confidence: Confidence = Confidence.medium
    evidence: list[str] = Field(default_factory=list)


class AttackSurfaceItem(BaseModel):
    id: str = Field(default_factory=lambda: new_id("route"))
    route: str
    method: str = "GET"
    file: str
    handler: str | None = None
    middleware: list[str] = Field(default_factory=list)
    authentication: str = "unknown"
    authorization: str = "unknown"
    input_sources: list[str] = Field(default_factory=list)
    validation: str = "unknown"
    database_access: list[str] = Field(default_factory=list)
    file_access: list[str] = Field(default_factory=list)
    external_calls: list[str] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    sensitive_output: bool = False
    tenant_scope: str = "unknown"
    admin_scope: bool = False
    rate_limiting: str = "unknown"
    csrf: str = "unknown"
    cors: str = "unknown"


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    file: str | None = None
    line: int | None = None
    risk: Severity | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str


class CodeGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class Evidence(BaseModel):
    source: str
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    route: str | None = None
    endpoint: str | None = None
    symbol: str | None = None
    package: str | None = None
    cve: str | None = None
    raw_artifact_id: str | None = None
    snippet: str | None = None
    message: str


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fnd"))
    project_id: str | None = None
    scan_id: str | None = None
    scanner_run_id: str | None = None
    scanner: str | None = None
    original_rule_id: str | None = None
    nope_rule_id: str | None = None
    fingerprint: str
    title: str
    description: str
    severity: Severity
    original_severity: str | None = None
    confidence: Confidence
    original_confidence: str | None = None
    category: str
    cwe: str | None = None
    owasp: str | None = None
    affected_file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    affected_route: str | None = None
    endpoint: str | None = None
    package: str | None = None
    cve: str | None = None
    raw_artifact_id: str | None = None
    code_flow_fingerprint: str | None = None
    scanner_sources: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    attack_scenario: str | None = None
    impact: str | None = None
    remediation: str
    test_guidance: str | None = None
    status: str = FindingStatus.new.value
    verification_state: str = "unverified"
    ai_review_state: str = "not_reviewed"
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)
    recurrence_count: int = 1
    baseline_state: BaselineState = BaselineState.new
    suppression: Suppression | None = None
    suppression_expired_at: datetime | None = None
    fix_available: bool = False
    verified: bool = False


class ScannerRun(BaseModel):
    scanner: str
    version: str = "unknown"
    status: Literal["passed", "failed", "skipped"]
    coverage_categories: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=now_utc)
    completed_at: datetime = Field(default_factory=now_utc)
    message: str = ""
    findings_count: int = 0
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    raw_stdout: str = ""
    raw_stderr: str = ""
    raw_artifact_id: str | None = None
    raw_artifact_url: str | None = None


class CoverageRecord(BaseModel):
    domain: str
    status: CoverageStatus
    scanners: list[str] = Field(default_factory=list)
    notes: str = ""


class AIReview(BaseModel):
    status: Literal["Complete", "Partial", "Not tested", "Failed"] = "Not tested"
    provider: str = "none"
    model: str | None = None
    evidence_provided: list[str] = Field(default_factory=list)
    confidence: Confidence | None = None
    missing_context: list[str] = Field(default_factory=list)
    message: str = "AI runtime not configured."


class ScanRequest(BaseModel):
    project_id: str | None = None
    mode: ScanMode
    target_url: HttpUrl | None = None
    authorization: AuthorizationScope | None = None
    scan_depth: Literal["quick", "full", "deep"] = "quick"
    repository_name: str | None = None
    branch: str | None = None
    commit_sha: str | None = None


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: new_id("scan"))
    project_id: str | None = None
    mode: ScanMode
    status: Literal["queued", "preparing", "running", "partial", "completed", "failed", "cancelled"] = "queued"
    verdict: str = "Maybe. Coverage is incomplete."
    score: int = 0
    coverage_percent: int = 0
    target_url: str | None = None
    repository_name: str | None = None
    repository_workspace_path: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    started_at: datetime = Field(default_factory=now_utc)
    completed_at: datetime | None = None
    stages: list[dict[str, Any]] = Field(default_factory=list)
    stack: list[StackEvidence] = Field(default_factory=list)
    attack_surface: list[AttackSurfaceItem] = Field(default_factory=list)
    code_graph: CodeGraph = Field(default_factory=CodeGraph)
    scanner_runs: list[ScannerRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    coverage: list[CoverageRecord] = Field(default_factory=list)
    ai_review: AIReview = Field(default_factory=AIReview)
    report_formats: list[str] = Field(default_factory=lambda: ["json", "md", "sarif", "pdf"])
