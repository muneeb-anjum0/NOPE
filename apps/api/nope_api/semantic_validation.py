from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from nope_api.models import DataSensitivity, ExecutionContext, Finding, Reachability, Severity

SERVER_ROUTE_PATTERNS = (
    re.compile(r"\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(", re.I),
    re.compile(r"@(?:app|router|\w+_router)\.(?:get|post|put|patch|delete)\s*\(", re.I),
    re.compile(r"@app\.route\s*\(", re.I),
    re.compile(r"\bpath\s*\(\s*['\"]", re.I),
    re.compile(r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b"),
)
SOURCE_RE = re.compile(
    r"\b(process\.env\.[A-Z0-9_]+|os\.environ|cookies?\(|session\.|req\.(?:body|query|params)|request\.(?:json|formData)\()",
    re.I,
)
EXPOSURE_SINK_RE = re.compile(
    r"\b(NextResponse\.json|Response\.json|res\.json|res\.send|JSONResponse|render\(|console\.(?:log|error|warn)|logger\.|fetch\(|axios\.|telemetry|analytics)\b",
    re.I,
)
DANGEROUS_SINK_RE = re.compile(
    r"\b(exec|execSync|spawn|system|popen|eval|raw\s*\(|query\s*\(|redirect\s*\(|writeFile|requests?\.(?:get|post)|fetch)\s*\(",
    re.I,
)
AUTH_RE = re.compile(
    r"\b(requireAuth|withAuth|getServerSession|auth\(|session\.user|currentUser|permission_classes|Depends\s*\([^)]*auth|auth\.uid)\b",
    re.I,
)
AUTHZ_RE = re.compile(
    r"\b((?:ownerId|owner_id|tenantId|tenant_id|organizationId|workspaceId|userId)\s*:\s*(?:session|user|auth)|auth\.uid\(\))\b",
    re.I,
)
SENSITIVE_NAME_RE = re.compile(
    r"(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE|ACCESS_KEY|CREDENTIAL)", re.I
)
PUBLIC_CONFIG_RE = re.compile(
    r"^(?:NEXT_PUBLIC_(?:SITE_URL|APP_URL|STRIPE_PUBLISHABLE_KEY)|VITE_(?:SITE_URL|APP_URL)|NODE_ENV|PORT)$",
    re.I,
)
OPERATIONAL_RE = re.compile(
    r"(?:VERSION|BUILD|COMMIT|TIMESTAMP|NODE_ENV|PORT|DATA_DIR|STATIC_EXPORT|SITE_URL)", re.I
)
HARDCODED_CREDENTIAL_RE = re.compile(
    r"\b(?:api[_-]?key|password|secret|token|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]",
    re.I,
)
KEYWORD_RE = re.compile(
    r"\b(internal|private|preview|staging|environment|localhost|admin|secret|token|debug|api)\b",
    re.I,
)
TYPE_ONLY_RE = re.compile(r"(?m)^\s*(?:export\s+)?(?:interface|type)\s+\w+")


@dataclass
class RouteFact:
    path: str
    file: str
    auth: bool
    authorization: bool
    sensitive_output: bool


@dataclass
class SemanticRepositoryContext:
    file_contexts: dict[str, set[ExecutionContext]] = field(default_factory=dict)
    routes: list[RouteFact] = field(default_factory=list)
    reachability: Reachability = Reachability.unknown
    reachability_evidence: list[str] = field(default_factory=list)


@dataclass
class SemanticDecision:
    contract: str
    outcome: str
    reason_code: str
    reason: str
    proof: list[dict[str, str]] = field(default_factory=list)
    negative_evidence: list[str] = field(default_factory=list)
    severity: Severity | None = None


def build_semantic_context(root: Path | None) -> SemanticRepositoryContext:
    context = SemanticRepositoryContext()
    if not root or not root.exists():
        return context
    compose_texts: list[tuple[str, str]] = []
    docker_expose = False
    server_bind_all = False
    for path in root.rglob("*"):
        if not path.is_file() or any(
            part in {".git", "node_modules", ".next", "dist", "build", "vendor"}
            for part in path.parts
        ):
            continue
        rel = path.relative_to(root).as_posix()
        text = _read(path)
        contexts = classify_execution_context(rel, text)
        context.file_contexts[rel] = contexts
        if ExecutionContext.server_runtime in contexts:
            context.routes.extend(_discover_routes(rel, text))
        lowered = path.name.lower()
        if lowered in {
            "compose.yml",
            "compose.yaml",
            "docker-compose.yml",
            "docker-compose.yaml",
        } or lowered.startswith("docker-compose."):
            compose_texts.append((rel, text))
        if lowered == "dockerfile" or lowered.startswith("dockerfile."):
            docker_expose |= bool(re.search(r"(?im)^\s*EXPOSE\s+\d+", text))
        server_bind_all |= bool(
            re.search(
                r"(?:host\s*[:=]\s*['\"]0\.0\.0\.0|--host\s+0\.0\.0\.0|listen\s+0\.0\.0\.0)",
                text,
                re.I,
            )
        )
    loopback = []
    public = []
    internal = []
    for rel, text in compose_texts:
        for match in re.finditer(r"(?m)^\s*-\s*['\"]?([^\s#'\"]+:[^\s#'\"]+)['\"]?\s*$", text):
            mapping = match.group(1)
            if mapping.startswith("127.0.0.1:") or mapping.startswith("localhost:"):
                loopback.append(f"{rel}: {mapping}")
            elif mapping.count(":") >= 1:
                public.append(f"{rel}: {mapping}")
        if re.search(r"(?m)^\s*expose\s*:", text):
            internal.append(f"{rel}: Compose expose is container-internal metadata")
    if public:
        context.reachability = Reachability.public_internet
        context.reachability_evidence = public
    elif loopback:
        context.reachability = Reachability.host_loopback
        context.reachability_evidence = loopback + (
            ["Server binds all container interfaces, but host publishing is loopback-only."]
            if server_bind_all
            else []
        )
    elif internal or docker_expose:
        context.reachability = Reachability.container_internal
        context.reachability_evidence = internal + (
            ["Dockerfile EXPOSE is metadata and does not prove host publishing."]
            if docker_expose
            else []
        )
    return context


def classify_execution_context(rel: str, text: str) -> set[ExecutionContext]:
    lower = rel.lower()
    labels: set[ExecutionContext] = set()
    if re.search(r"(^|/)(tests?|__tests__|spec|e2e)(/|$)|\.(?:test|spec)\.[^.]+$", lower):
        labels.add(ExecutionContext.test)
    if "playwright" in lower or "cypress" in lower:
        labels.update(
            {ExecutionContext.test, ExecutionContext.e2e_test, ExecutionContext.configuration}
        )
    if re.search(r"(^|/)(fixtures?|testdata|mocks?|__mocks__)(/|$)", lower):
        labels.add(
            ExecutionContext.fixture
            if "fixture" in lower or "testdata" in lower
            else ExecutionContext.mock
        )
    if "benchmark" in lower:
        labels.add(ExecutionContext.benchmark)
    if lower.endswith((".md", ".rst", ".txt")) or "/docs/" in f"/{lower}":
        labels.add(ExecutionContext.documentation)
    if lower.endswith(".d.ts") or (
        TYPE_ONLY_RE.search(text) and not _has_executable_statements(text)
    ):
        labels.add(ExecutionContext.type_only)
    if re.search(r"(^|/)(generated|vendor|dist|build)(/|$)", lower):
        labels.add(
            ExecutionContext.generated if "generated" in lower else ExecutionContext.vendored
        )
    if re.search(r"(^|/)(migrations?|alembic)(/|$)", lower):
        labels.add(ExecutionContext.migration)
    if re.search(r"(^|/)(\.github/workflows|\.gitlab-ci|ci)(/|$)", lower):
        labels.add(ExecutionContext.ci)
    if re.search(
        r"(?:next|vite|webpack|rollup|playwright|jest|vitest)\.config\.", lower
    ) or lower.endswith(("package.json", "tsconfig.json")):
        labels.update({ExecutionContext.build_time, ExecutionContext.configuration})
    if (
        Path(lower).name
        in {
            "dockerfile",
            "compose.yml",
            "compose.yaml",
            "docker-compose.yml",
            "docker-compose.yaml",
        }
        or "ingress" in lower
    ):
        labels.add(ExecutionContext.deployment_configuration)
    if _is_server_route(rel, text):
        labels.update({ExecutionContext.production_runtime, ExecutionContext.server_runtime})
    elif lower.endswith((".tsx", ".jsx", ".vue", ".svelte")) and (
        "use client" in text
        or re.search(r"\bReact\b|from ['\"]react|\b(?:localStorage|window|document)\b", text)
    ):
        labels.add(ExecutionContext.client_runtime)
    elif lower.endswith(
        (".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".php", ".go", ".rs", ".cs")
    ) and not labels.intersection(
        {ExecutionContext.test, ExecutionContext.type_only, ExecutionContext.build_time}
    ):
        labels.add(ExecutionContext.production_runtime)
    return labels or {ExecutionContext.unknown}


def evaluate_semantic_finding(
    finding: Finding, root: Path | None, context: SemanticRepositoryContext
) -> SemanticDecision | None:
    rel = finding.affected_file or ""
    # Historical/native observations without a source location cannot be
    # reclassified by repository semantics; preserve their existing gate path.
    if not rel:
        return None
    text = _read(root / rel) if root and rel and (root / rel).is_file() else ""
    labels = context.file_contexts.get(rel, {ExecutionContext.unknown})
    finding.execution_contexts = sorted(labels, key=lambda item: item.value)
    finding.reachability = context.reachability
    finding.data_sensitivity = classify_sensitivity(finding, text)
    family = _family(finding)
    contextual = family in {
        "secret_exposure",
        "information_disclosure",
        "debug_endpoint",
        "staging_exposure",
        "authorization",
        "rate_limit",
        "ai_cost",
        "open_redirect",
        "command_injection",
        "route_exposure",
    }
    if not contextual:
        return None
    proof = [
        {"fact": "execution_context", "status": label.value, "evidence": rel or "No affected file"}
        for label in sorted(labels, key=lambda item: item.value)
    ]
    if labels.intersection(
        {
            ExecutionContext.test,
            ExecutionContext.e2e_test,
            ExecutionContext.fixture,
            ExecutionContext.mock,
            ExecutionContext.benchmark,
        }
    ):
        return SemanticDecision(
            family,
            "rejected",
            "REJECTED_TEST_ONLY_CONTEXT",
            "The signal is confined to test, fixture, mock, or benchmark context.",
            proof,
            ["No production runtime path was proven."],
        )
    if ExecutionContext.type_only in labels:
        return SemanticDecision(
            family,
            "rejected",
            "REJECTED_TYPE_ONLY_CONTEXT",
            "A type-only declaration cannot prove runtime security behavior.",
            proof,
            ["The affected file contains no executable runtime path."],
        )
    if labels.intersection(
        {ExecutionContext.build_time, ExecutionContext.documentation}
    ) and not labels.intersection(
        {ExecutionContext.server_runtime, ExecutionContext.client_runtime}
    ):
        return SemanticDecision(
            family,
            "rejected",
            "REJECTED_BUILD_ONLY_CONTEXT",
            "Build-time or documentation context does not prove deployed runtime exposure.",
            proof,
            ["No deployed runtime execution was proven."],
        )
    has_source = bool(SOURCE_RE.search(text))
    has_exposure_sink = bool(EXPOSURE_SINK_RE.search(text))
    has_dangerous_sink = bool(DANGEROUS_SINK_RE.search(text))
    route = _matching_route(finding, context)
    if (
        family
        in {
            "debug_endpoint",
            "staging_exposure",
            "route_exposure",
            "information_disclosure",
            "authorization",
            "rate_limit",
            "ai_cost",
        }
        and not route
    ):
        if (
            family == "authorization"
            and ExecutionContext.client_runtime in labels
            and re.search(
                r"\b(?:localStorage|sessionStorage)[\s\S]*(?:admin|role|tenant|owner)",
                text,
                re.I,
            )
        ):
            proof.append(
                {
                    "fact": "client_only_authorization",
                    "status": "VERIFIED",
                    "evidence": "Browser storage controls privileged UI behavior.",
                }
            )
            return SemanticDecision(
                family,
                "promoted",
                "PROMOTED_VERIFIED_AUTHZ_GAP",
                "Privileged behavior is controlled only by browser-owned state, "
                "which is not an authorization boundary.",
                proof,
                severity=finding.severity,
            )
        proof.append(
            {
                "fact": "server_route",
                "status": "NOT_PROVEN",
                "evidence": "No framework-resolved server route matched.",
            }
        )
        return SemanticDecision(
            family,
            "rejected",
            "REJECTED_NO_SERVER_ROUTE",
            "A string, schema, or client call cannot prove that a server route exists.",
            proof,
            ["No framework-resolved server route was discovered."],
        )
    if route:
        proof.append(
            {
                "fact": "server_route",
                "status": "VERIFIED",
                "evidence": f"{route.file}: {route.path}",
            }
        )
    if family in {"secret_exposure", "information_disclosure"}:
        native_rule = (finding.original_rule_id or finding.nope_rule_id or "").upper()
        native_hardcoded = native_rule == "NOPE-SEC-001" and bool(
            re.search(r"['\"][^'\"\n]{12,}['\"]", text)
        )
        env_credential = native_rule == "NOPE-ENV-001" and bool(
            re.search(
                r"(?im)^(?:[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY)|DATABASE_URL)\s*=\s*\S{12,}",
                text,
            )
        )
        if family == "secret_exposure" and (
            HARDCODED_CREDENTIAL_RE.search(text)
            or native_hardcoded
            or env_credential
            or (
                "gitleaks" in (finding.scanner or "").lower()
                and finding.data_sensitivity
                in {DataSensitivity.auth_credential, DataSensitivity.critical_secret}
            )
        ):
            proof.append(
                {
                    "fact": "hardcoded_credential",
                    "status": "VERIFIED",
                    "evidence": "Credential assignment in production source",
                }
            )
            return SemanticDecision(
                family,
                "promoted",
                "PROMOTED_VERIFIED_SOURCE_SINK",
                "A non-placeholder hardcoded credential is itself a security exposure "
                "and does not require an HTTP route.",
                proof,
                severity=finding.severity,
            )
        if finding.data_sensitivity == DataSensitivity.public_metadata:
            return SemanticDecision(
                family,
                "rejected",
                "REJECTED_PUBLIC_CONFIG_NOT_SECRET",
                "The value is intentionally public configuration or public metadata, not a secret.",
                proof,
                ["Semantic variable classification is PUBLIC_METADATA."],
            )
        if not has_source:
            return SemanticDecision(
                family,
                "rejected",
                "REJECTED_NO_SENSITIVE_SOURCE",
                "No sensitive runtime source was proven.",
                proof,
                ["No sensitive source expression exists in the affected runtime context."],
            )
        proof.append(
            {
                "fact": "sensitive_source",
                "status": "VERIFIED",
                "evidence": SOURCE_RE.search(text).group(0),
            }
        )
        if not has_exposure_sink:
            return SemanticDecision(
                family,
                "rejected",
                "REJECTED_NO_EXPOSURE_SINK",
                "Reading configuration or a secret does not prove exposure; no response, "
                "client, log, artifact, or third-party sink was found.",
                proof,
                ["Sensitive value remains in server/configuration flow."],
            )
        proof.append(
            {
                "fact": "exposure_sink",
                "status": "VERIFIED",
                "evidence": EXPOSURE_SINK_RE.search(text).group(0),
            }
        )
    if family in {"open_redirect", "command_injection"} and not has_dangerous_sink:
        return SemanticDecision(
            family,
            "withheld",
            "WITHHELD_SOURCE_SINK_INCOMPLETE",
            "A dangerous source-to-sink path was not complete.",
            proof,
            ["Required execution sink was not proven."],
        )
    if route and family == "authorization" and (route.auth or route.authorization):
        return SemanticDecision(
            family,
            "rejected",
            "REJECTED_EFFECTIVE_AUTH_PRESENT",
            "Effective authentication or ownership/tenant authorization was found "
            "on the server route.",
            proof,
            ["Authorization helper or owner/tenant predicate is present."],
        )
    if route and family in {
        "debug_endpoint",
        "staging_exposure",
        "information_disclosure",
        "route_exposure",
    }:
        proof.append(
            {
                "fact": "reachability",
                "status": context.reachability.value,
                "evidence": "; ".join(context.reachability_evidence)
                or "No deployment publishing evidence",
            }
        )
        if context.reachability == Reachability.host_loopback:
            return SemanticDecision(
                family,
                "rejected",
                "REJECTED_LOOPBACK_ONLY",
                "The effective host publishing is loopback-only.",
                proof,
                context.reachability_evidence,
                Severity.info,
            )
        if context.reachability == Reachability.container_internal:
            return SemanticDecision(
                family,
                "rejected",
                "REJECTED_CONTAINER_INTERNAL_ONLY",
                "Container listening or Docker EXPOSE does not prove external reachability.",
                proof,
                context.reachability_evidence,
                Severity.info,
            )
        if context.reachability == Reachability.unknown:
            return SemanticDecision(
                family,
                "withheld",
                "WITHHELD_REACHABILITY_UNKNOWN",
                "The server route exists, but public reachability is unknown and was not guessed.",
                proof,
                ["No host publishing, proxy, or ingress proof was discovered."],
            )
    if KEYWORD_RE.search(text) and not (route or has_exposure_sink or has_dangerous_sink):
        return SemanticDecision(
            family,
            "rejected",
            "REJECTED_KEYWORD_ONLY_MATCH",
            "Security-sounding words are context hints, not proof of a vulnerability.",
            proof,
            ["No executable security behavior was correlated."],
        )
    proof.append({"fact": "proof_contract", "status": "SATISFIED", "evidence": family})
    severity = _impact_severity(finding, context)
    return SemanticDecision(
        family,
        "promoted",
        _promotion_code(family),
        "The vulnerability-family proof contract has deterministic runtime, behavior, "
        "and exposure evidence.",
        proof,
        severity=severity,
    )


def classify_sensitivity(finding: Finding, text: str) -> DataSensitivity:
    names = re.findall(r"process\.env\.([A-Z0-9_]+)", text, re.I)
    if any(
        name.upper().startswith(("NEXT_PUBLIC_", "VITE_")) and SENSITIVE_NAME_RE.search(name)
        for name in names
    ):
        return DataSensitivity.critical_secret
    if any(PUBLIC_CONFIG_RE.match(name) for name in names):
        return DataSensitivity.public_metadata
    if any(SENSITIVE_NAME_RE.search(name) for name in names) or re.search(
        r"(?:password|secret|private[_-]?key|access[_-]?token)",
        finding.title + " " + finding.description,
        re.I,
    ):
        return DataSensitivity.auth_credential
    if any(OPERATIONAL_RE.search(name) for name in names) or re.search(
        r"\b(version|build timestamp|commit sha|node_env|site url)\b",
        finding.title + " " + finding.description,
        re.I,
    ):
        return DataSensitivity.operational_metadata
    return DataSensitivity.unknown


def _discover_routes(rel: str, text: str) -> list[RouteFact]:
    paths = re.findall(
        r"(?:route|\.get|\.post|\.put|\.patch|\.delete)\s*\(\s*['\"]([^'\"]+)", text, re.I
    )
    if "app/api/" in rel.lower() and "/route." in rel.lower():
        part = rel.lower().split("app/api/", 1)[1].rsplit("/route.", 1)[0]
        paths.append("/api/" + re.sub(r"\[([^]]+)\]", r"{\1}", part))
    if "pages/api/" in rel.lower():
        part = rel.lower().split("pages/api/", 1)[1].rsplit(".", 1)[0]
        paths.append("/api/" + part)
    if not paths and _generic_api_module(rel, text):
        paths.append("/api/" + Path(rel).stem.replace("-", "/"))
    if not paths and any(pattern.search(text) for pattern in SERVER_ROUTE_PATTERNS):
        paths.append("unknown-framework-route")
    return [
        RouteFact(
            path,
            rel,
            bool(AUTH_RE.search(text)),
            bool(AUTHZ_RE.search(text)),
            bool(EXPOSURE_SINK_RE.search(text)),
        )
        for path in sorted(set(paths))
    ]


def _is_server_route(rel: str, text: str) -> bool:
    lower = rel.lower()
    return (
        ("app/api/" in lower and "/route." in lower)
        or "pages/api/" in lower
        or _generic_api_module(rel, text)
        or any(pattern.search(text) for pattern in SERVER_ROUTE_PATTERNS)
    )


def _generic_api_module(rel: str, text: str) -> bool:
    lower = rel.lower()
    return bool(
        (lower.startswith("src/api/") or "/src/api/" in lower)
        and re.search(r"\bexport\s+(?:async\s+)?(?:function|const)\b", text)
    )


def _matching_route(finding: Finding, context: SemanticRepositoryContext) -> RouteFact | None:
    rel = (finding.affected_file or "").lower()
    requested = finding.affected_route or finding.endpoint
    for route in context.routes:
        if route.file.lower() == rel or (requested and route.path == requested):
            return route
    return None


def _family(finding: Finding) -> str:
    value = " ".join(
        filter(
            None,
            [
                finding.category,
                finding.title,
                finding.description,
                finding.original_rule_id,
                finding.nope_rule_id,
            ],
        )
    ).lower()
    if "debug" in value:
        return "debug_endpoint"
    if "staging" in value or "preview" in value:
        return "staging_exposure"
    if "secret" in value or "environment" in value or "credential" in value:
        return "secret_exposure"
    if "information" in value or "metadata" in value or "version" in value:
        return "information_disclosure"
    if "auth" in value or "idor" in value or "tenant" in value:
        return "authorization"
    if "rate" in value:
        return "rate_limit"
    if "ai" in value and ("cost" in value or "exhaust" in value):
        return "ai_cost"
    if "redirect" in value:
        return "open_redirect"
    if "command" in value or "shell" in value:
        return "command_injection"
    if "expos" in value or "public route" in value:
        return "route_exposure"
    return "other"


def _impact_severity(finding: Finding, context: SemanticRepositoryContext) -> Severity:
    if finding.data_sensitivity in {
        DataSensitivity.operational_metadata,
        DataSensitivity.public_metadata,
    }:
        return (
            Severity.low if context.reachability == Reachability.public_internet else Severity.info
        )
    return finding.severity


def _promotion_code(family: str) -> str:
    return {
        "secret_exposure": "PROMOTED_VERIFIED_SOURCE_SINK",
        "authorization": "PROMOTED_VERIFIED_AUTHZ_GAP",
        "debug_endpoint": "PROMOTED_VERIFIED_PUBLIC_ROUTE",
        "staging_exposure": "PROMOTED_VERIFIED_PUBLIC_ROUTE",
    }.get(family, "PROMOTED_EFFECTIVE_RUNTIME_MISCONFIGURATION")


def _has_executable_statements(text: str) -> bool:
    stripped = TYPE_ONLY_RE.sub("", text)
    return bool(
        re.search(
            r"\b(function|const\s+\w+\s*=|let\s+\w+\s*=|class\s+\w+|return\s+|await\s+|new\s+\w+)\b",
            stripped,
        )
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
    except OSError:
        return ""
