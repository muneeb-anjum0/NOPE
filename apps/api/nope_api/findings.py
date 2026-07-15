from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal

from pydantic import BaseModel, Field

from nope_api.models import Finding, GraphEdge, GraphNode, Scan
from nope_api.rag import redact_text


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FindingFilters(BaseModel):
    severity: list[str] = Field(default_factory=list)
    confidence: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    scanner: list[str] = Field(default_factory=list)
    rule: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    file: str | None = None
    route: str | None = None
    first_seen: str | None = None
    new: bool | None = None
    fixed: bool | None = None
    reintroduced: bool | None = None
    suppressed: bool | None = None
    ai_reviewed: bool | None = None
    verified: bool | None = None
    fix_available: bool | None = None
    query: str | None = None


class FindingQueryResult(BaseModel):
    scan_id: str
    total: int
    page: int
    page_size: int
    pages: int
    sort: str
    direction: Literal["asc", "desc"]
    filters: FindingFilters
    items: list[Finding]


class SourceSnippet(BaseModel):
    file: str
    start_line: int
    end_line: int
    language: str
    code: str
    highlighted_lines: list[int] = Field(default_factory=list)
    available: bool = True
    message: str = ""


class FindingHistoryItem(BaseModel):
    event: str
    at: str
    data: dict[str, Any] = Field(default_factory=dict)


class FindingDetail(BaseModel):
    finding: Finding
    evidence: list[dict[str, Any]]
    source: SourceSnippet | None
    code_flow: dict[str, Any]
    history: list[FindingHistoryItem]
    tabs: list[str] = Field(default_factory=lambda: ["overview", "evidence", "code", "code_flow", "fix", "tests", "history"])


@dataclass(frozen=True)
class ParsedFindingQuery:
    filters: FindingFilters
    page: int
    page_size: int
    sort: str
    direction: Literal["asc", "desc"]


def _split_csv(values: Iterable[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    result: list[str] = []
    for value in values:
        result.extend(part.strip().lower() for part in str(value).split(",") if part.strip())
    return sorted(set(result))


def parse_bool(value: str | bool | None) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None


def parse_finding_query(
    *,
    severity: str | None = None,
    confidence: str | None = None,
    status: str | None = None,
    scanner: str | None = None,
    rule: str | None = None,
    cwe: str | None = None,
    owasp: str | None = None,
    file: str | None = None,
    route: str | None = None,
    first_seen: str | None = None,
    new: str | bool | None = None,
    fixed: str | bool | None = None,
    reintroduced: str | bool | None = None,
    suppressed: str | bool | None = None,
    ai_reviewed: str | bool | None = None,
    verified: str | bool | None = None,
    fix_available: str | bool | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = 25,
    sort: str = "severity",
    direction: str = "asc",
) -> ParsedFindingQuery:
    return ParsedFindingQuery(
        filters=FindingFilters(
            severity=_split_csv(severity),
            confidence=_split_csv(confidence),
            status=_split_csv(status),
            scanner=_split_csv(scanner),
            rule=_split_csv(rule),
            cwe=_split_csv(cwe),
            owasp=_split_csv(owasp),
            file=file.strip() if file else None,
            route=route.strip() if route else None,
            first_seen=first_seen.strip() if first_seen else None,
            new=parse_bool(new),
            fixed=parse_bool(fixed),
            reintroduced=parse_bool(reintroduced),
            suppressed=parse_bool(suppressed),
            ai_reviewed=parse_bool(ai_reviewed),
            verified=parse_bool(verified),
            fix_available=parse_bool(fix_available),
            query=query.strip() if query else None,
        ),
        page=max(1, page),
        page_size=max(1, min(page_size, 100)),
        sort=sort if sort in {"severity", "confidence", "status", "scanner", "file", "route", "first_seen", "last_seen", "title"} else "severity",
        direction="desc" if direction == "desc" else "asc",
    )


def query_findings(scan: Scan, parsed: ParsedFindingQuery) -> FindingQueryResult:
    items = [finding for finding in scan.findings if _matches(finding, parsed.filters)]
    items = _sort_findings(items, parsed.sort, parsed.direction)
    total = len(items)
    pages = max(1, (total + parsed.page_size - 1) // parsed.page_size)
    page = min(parsed.page, pages)
    start = (page - 1) * parsed.page_size
    return FindingQueryResult(
        scan_id=scan.id,
        total=total,
        page=page,
        page_size=parsed.page_size,
        pages=pages,
        sort=parsed.sort,
        direction=parsed.direction,
        filters=parsed.filters,
        items=items[start : start + parsed.page_size],
    )


def _matches(finding: Finding, filters: FindingFilters) -> bool:
    if filters.severity and finding.severity.value not in filters.severity:
        return False
    if filters.confidence and finding.confidence.value not in filters.confidence:
        return False
    if filters.status and finding.status.lower() not in filters.status:
        return False
    if filters.scanner and not set(source.lower() for source in finding.scanner_sources + ([finding.scanner] if finding.scanner else [])) & set(filters.scanner):
        return False
    if filters.rule:
        rules = {value.lower() for value in [finding.original_rule_id, finding.nope_rule_id] if value}
        if not rules & set(filters.rule):
            return False
    if filters.cwe and (finding.cwe or "").lower() not in filters.cwe:
        return False
    if filters.owasp and (finding.owasp or "").lower() not in filters.owasp:
        return False
    if filters.file and filters.file.lower() not in (finding.affected_file or "").lower():
        return False
    if filters.route and filters.route.lower() not in (finding.affected_route or "").lower():
        return False
    if filters.first_seen and finding.first_seen.date().isoformat() < filters.first_seen:
        return False
    if filters.new is not None and (finding.baseline_state.value == "new") is not filters.new:
        return False
    if filters.fixed is not None and (finding.status == "fixed") is not filters.fixed:
        return False
    if filters.reintroduced is not None and (finding.status == "reintroduced" or finding.baseline_state.value == "reintroduced") is not filters.reintroduced:
        return False
    if filters.suppressed is not None and (finding.status == "suppressed") is not filters.suppressed:
        return False
    if filters.ai_reviewed is not None and (finding.ai_review_state != "not_reviewed") is not filters.ai_reviewed:
        return False
    if filters.verified is not None and finding.verified is not filters.verified:
        return False
    if filters.fix_available is not None and finding.fix_available is not filters.fix_available:
        return False
    if filters.query:
        haystack = " ".join(
            [
                finding.title,
                finding.description,
                finding.category,
                finding.affected_file or "",
                finding.affected_route or "",
                finding.remediation,
                " ".join(evidence.message for evidence in finding.evidence),
            ]
        ).lower()
        if filters.query.lower() not in haystack:
            return False
    return True


def _sort_findings(findings: list[Finding], sort: str, direction: Literal["asc", "desc"]) -> list[Finding]:
    reverse = direction == "desc"

    def key(finding: Finding) -> Any:
        if sort == "severity":
            return SEVERITY_ORDER.get(finding.severity.value, 99)
        if sort == "confidence":
            return {"confirmed": 0, "high": 1, "medium": 2, "low": 3, "uncertain": 4}.get(finding.confidence.value, 99)
        if sort == "status":
            return finding.status
        if sort == "scanner":
            return ",".join(finding.scanner_sources)
        if sort == "file":
            return finding.affected_file or ""
        if sort == "route":
            return finding.affected_route or ""
        if sort == "first_seen":
            return finding.first_seen
        if sort == "last_seen":
            return finding.last_seen
        return finding.title.lower()

    return sorted(findings, key=key, reverse=reverse)


def finding_detail(scan: Scan, finding_id: str) -> FindingDetail | None:
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if finding is None:
        return None
    return FindingDetail(
        finding=finding,
        evidence=[evidence.model_dump(mode="json") for evidence in finding.evidence],
        source=_source_snippet(scan, finding),
        code_flow=_code_flow(scan, finding),
        history=[
            FindingHistoryItem(event="first_seen", at=finding.first_seen.isoformat(), data={"baseline_state": finding.baseline_state.value}),
            FindingHistoryItem(event=finding.status, at=finding.last_seen.isoformat(), data={"recurrence_count": finding.recurrence_count}),
        ],
    )


def _source_snippet(scan: Scan, finding: Finding) -> SourceSnippet | None:
    file = finding.affected_file or next((evidence.file for evidence in finding.evidence if evidence.file), None)
    if not file:
        return None
    root = Path(scan.repository_workspace_path or "")
    path = root / file
    if not root or not path.exists() or not path.is_file():
        return SourceSnippet(file=file, start_line=finding.start_line or 1, end_line=finding.end_line or finding.start_line or 1, language=_language(file), code="", highlighted_lines=[], available=False, message="Source file is not available in the current workspace.")
    text = redact_text(path.read_text(encoding="utf-8", errors="ignore"))
    lines = text.splitlines()
    target = finding.start_line or next((evidence.line for evidence in finding.evidence if evidence.line), None) or 1
    end_target = finding.end_line or target
    start = max(1, target - 8)
    end = min(len(lines), end_target + 8)
    return SourceSnippet(
        file=file,
        start_line=start,
        end_line=end,
        language=_language(file),
        code="\n".join(lines[start - 1 : end]),
        highlighted_lines=list(range(target, end_target + 1)),
    )


def _language(file: str) -> str:
    suffix = Path(file).suffix.lower()
    return {
        ".ts": "typescript",
        ".tsx": "tsx",
        ".js": "javascript",
        ".jsx": "jsx",
        ".py": "python",
        ".sql": "sql",
        ".json": "json",
        ".tf": "terraform",
        ".yml": "yaml",
        ".yaml": "yaml",
    }.get(suffix, "text")


def _code_flow(scan: Scan, finding: Finding) -> dict[str, Any]:
    file = finding.affected_file
    route = finding.affected_route
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    node_ids: set[str] = set()
    for node in scan.code_graph.nodes:
        if (file and node.file == file) or (route and route in node.label):
            nodes.append(node)
            node_ids.add(node.id)
    for edge in scan.code_graph.edges:
        if edge.source in node_ids or edge.target in node_ids:
            edges.append(edge)
            node_ids.update([edge.source, edge.target])
    if node_ids:
        node_by_id = {node.id: node for node in scan.code_graph.nodes}
        nodes = [node for node_id, node in node_by_id.items() if node_id in node_ids]
    return {
        "available": bool(nodes or edges),
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "edges": [edge.model_dump(mode="json") for edge in edges],
        "message": "Real scan graph data." if nodes or edges else "No code-flow graph exists for this finding yet.",
    }


def raw_artifact(scan: Scan, artifact_id: str) -> dict[str, Any] | None:
    for run in scan.scanner_runs:
        if run.raw_artifact_id == artifact_id:
            return {
                "id": artifact_id,
                "scanner": run.scanner,
                "status": run.status,
                "command": run.command,
                "exit_code": run.exit_code,
                "stdout": redact_text(run.raw_stdout),
                "stderr": redact_text(run.raw_stderr),
            }
    return None
