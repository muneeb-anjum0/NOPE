from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, Field

from nope_api.models import CoverageRecord, Finding, Scan


DriftType = Literal[
    "new_finding",
    "fixed_finding",
    "recurring_finding",
    "reintroduced_finding",
    "severity_change",
    "confidence_change",
    "new_route",
    "removed_route",
    "new_dependency",
    "new_cve",
    "new_secret",
    "rls_policy_change",
    "weaker_cors",
    "weaker_headers",
    "new_tracker",
    "new_public_asset",
    "scanner_coverage_regression",
    "scanner_version_change",
    "rule_version_change",
    "model_version_change",
    "rag_version_change",
]


class DriftItem(BaseModel):
    type: DriftType
    fingerprint: str | None = None
    severity: str | None = None
    message: str
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)


class BaselineSnapshot(BaseModel):
    baseline_version: str = "phase-8-v1"
    scan_id: str
    commit_sha: str | None = None
    repository_snapshot: dict[str, Any] = Field(default_factory=dict)
    target: str | None = None
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    rule_versions: dict[str, str] = Field(default_factory=lambda: {"NOPE rules": "local"})
    model_version: str | None = None
    quantization: str | None = None
    rag_version: str = "phase-6-v1"
    timestamp: str
    coverage: list[dict[str, Any]] = Field(default_factory=list)
    findings: dict[str, dict[str, Any]] = Field(default_factory=dict)
    routes: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    stack: list[str] = Field(default_factory=list)


class ScanComparison(BaseModel):
    reference_scan_id: str | None
    current_scan_id: str
    baseline_id: str | None = None
    new: list[Finding] = Field(default_factory=list)
    fixed: list[dict[str, Any]] = Field(default_factory=list)
    reintroduced: list[Finding] = Field(default_factory=list)
    unchanged: list[Finding] = Field(default_factory=list)
    severity_changes: list[DriftItem] = Field(default_factory=list)
    confidence_changes: list[DriftItem] = Field(default_factory=list)
    coverage_difference: list[DriftItem] = Field(default_factory=list)
    scanner_difference: list[DriftItem] = Field(default_factory=list)
    stack_difference: list[DriftItem] = Field(default_factory=list)
    drift_events: list[DriftItem] = Field(default_factory=list)
    incremental_scope: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, int] = Field(default_factory=dict)


def baseline_snapshot(scan: Scan) -> BaselineSnapshot:
    return BaselineSnapshot(
        scan_id=scan.id,
        commit_sha=scan.commit_sha,
        repository_snapshot={
            "repository_name": scan.repository_name,
            "branch": scan.branch,
            "commit_sha": scan.commit_sha,
        },
        target=scan.target_url,
        scanner_versions={run.scanner: run.version for run in scan.scanner_runs},
        model_version=scan.ai_review.model,
        quantization="Q4_K_M" if scan.ai_review.model and "q4" in scan.ai_review.model.lower() else None,
        timestamp=(scan.completed_at or scan.started_at).isoformat(),
        coverage=[record.model_dump(mode="json") for record in scan.coverage],
        findings={finding.fingerprint: _finding_summary(finding) for finding in scan.findings},
        routes=sorted({item.route for item in scan.attack_surface}),
        dependencies=sorted({finding.package for finding in scan.findings if finding.package}),
        stack=sorted({item.technology for item in scan.stack}),
    )


def compare_scans(current: Scan, reference: Scan | BaselineSnapshot, *, baseline_id: str | None = None) -> ScanComparison:
    reference_findings = _reference_findings(reference)
    current_by_fp = {finding.fingerprint: finding for finding in current.findings}
    current_fps = set(current_by_fp)
    reference_fps = set(reference_findings)

    new = [current_by_fp[fp] for fp in sorted(current_fps - reference_fps)]
    fixed = [reference_findings[fp] for fp in sorted(reference_fps - current_fps)]
    unchanged = [current_by_fp[fp] for fp in sorted(current_fps & reference_fps)]
    reintroduced = [
        finding
        for finding in unchanged
        if finding.status == "reintroduced" or finding.baseline_state.value == "reintroduced" or reference_findings[finding.fingerprint].get("status") in {"fixed", "verified"}
    ]
    severity_changes = [
        DriftItem(
            type="severity_change",
            fingerprint=finding.fingerprint,
            severity=finding.severity.value,
            message=f"Severity changed for {finding.title}.",
            before={"severity": reference_findings[finding.fingerprint].get("severity")},
            after={"severity": finding.severity.value},
        )
        for finding in unchanged
        if reference_findings[finding.fingerprint].get("severity") != finding.severity.value
    ]
    confidence_changes = [
        DriftItem(
            type="confidence_change",
            fingerprint=finding.fingerprint,
            severity=finding.severity.value,
            message=f"Confidence changed for {finding.title}.",
            before={"confidence": reference_findings[finding.fingerprint].get("confidence")},
            after={"confidence": finding.confidence.value},
        )
        for finding in unchanged
        if reference_findings[finding.fingerprint].get("confidence") != finding.confidence.value
    ]

    drift_events = _finding_drift_items(new, fixed, reintroduced)
    coverage_difference = _coverage_drift(current, reference)
    scanner_difference = _scanner_drift(current, reference)
    stack_difference = _stack_drift(current, reference)
    drift_events.extend(severity_changes + confidence_changes + coverage_difference + scanner_difference + stack_difference)
    drift_events.extend(_version_drift(current, reference))
    drift_events.extend(_domain_drift(current, reference))

    return ScanComparison(
        reference_scan_id=_reference_scan_id(reference),
        current_scan_id=current.id,
        baseline_id=baseline_id,
        new=new,
        fixed=fixed,
        reintroduced=reintroduced,
        unchanged=unchanged,
        severity_changes=severity_changes,
        confidence_changes=confidence_changes,
        coverage_difference=coverage_difference,
        scanner_difference=scanner_difference,
        stack_difference=stack_difference,
        drift_events=drift_events,
        incremental_scope=_incremental_scope(current, reference, new, fixed, drift_events),
        summary={
            "new": len(new),
            "fixed": len(fixed),
            "reintroduced": len(reintroduced),
            "unchanged": len(unchanged),
            "severity_changes": len(severity_changes),
            "confidence_changes": len(confidence_changes),
            "coverage_drift": len(coverage_difference),
            "scanner_drift": len(scanner_difference),
            "total_drift_events": len(drift_events),
        },
    )


def _finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "status": finding.status,
        "category": finding.category,
        "file": finding.affected_file,
        "route": finding.affected_route,
        "package": finding.package,
        "cve": finding.cve,
        "scanner_sources": finding.scanner_sources,
    }


def _reference_findings(reference: Scan | BaselineSnapshot) -> dict[str, dict[str, Any]]:
    if isinstance(reference, Scan):
        return {finding.fingerprint: _finding_summary(finding) for finding in reference.findings}
    return reference.findings


def _reference_scan_id(reference: Scan | BaselineSnapshot) -> str | None:
    return reference.id if isinstance(reference, Scan) else reference.scan_id


def _finding_drift_items(new: list[Finding], fixed: list[dict[str, Any]], reintroduced: list[Finding]) -> list[DriftItem]:
    items: list[DriftItem] = []
    items.extend(
        DriftItem(type="new_finding", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"New finding: {finding.title}.", after=_finding_summary(finding))
        for finding in new
    )
    items.extend(
        DriftItem(type="fixed_finding", fingerprint=finding["fingerprint"], severity=finding.get("severity"), message=f"Fixed finding: {finding.get('title')}.", before=finding)
        for finding in fixed
    )
    items.extend(
        DriftItem(type="reintroduced_finding", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"Reintroduced finding: {finding.title}.", after=_finding_summary(finding))
        for finding in reintroduced
    )
    return items


def _coverage_map(source: Scan | BaselineSnapshot) -> dict[str, str]:
    if isinstance(source, Scan):
        return {record.domain: record.status.value for record in source.coverage}
    return {str(record.get("domain")): str(record.get("status")) for record in source.coverage}


def _coverage_drift(current: Scan, reference: Scan | BaselineSnapshot) -> list[DriftItem]:
    before = _coverage_map(reference)
    after = _coverage_map(current)
    items: list[DriftItem] = []
    for domain in sorted(set(before) | set(after)):
        old = before.get(domain)
        new = after.get(domain)
        if old and new and old != new:
            items.append(
                DriftItem(
                    type="scanner_coverage_regression" if _coverage_rank(new) > _coverage_rank(old) else "recurring_finding",
                    message=f"Coverage changed for {domain}: {old} -> {new}.",
                    severity="medium" if _coverage_rank(new) > _coverage_rank(old) else "info",
                    before={"domain": domain, "status": old},
                    after={"domain": domain, "status": new},
                )
            )
    return items


def _coverage_rank(status: str | None) -> int:
    return {"Verified": 0, "Partial": 1, "Not applicable": 1, "Not tested": 2, "Failed": 3}.get(status or "", 2)


def _scanner_drift(current: Scan, reference: Scan | BaselineSnapshot) -> list[DriftItem]:
    current_status = {run.scanner: run.status for run in current.scanner_runs}
    if isinstance(reference, Scan):
        reference_status = {run.scanner: run.status for run in reference.scanner_runs}
    else:
        reference_status = {name: "passed" for name in reference.scanner_versions}
    items: list[DriftItem] = []
    for scanner in sorted(set(current_status) | set(reference_status)):
        old = reference_status.get(scanner)
        new = current_status.get(scanner)
        if old != new:
            items.append(
                DriftItem(
                    type="scanner_coverage_regression" if new == "failed" else "recurring_finding",
                    message=f"Scanner status changed for {scanner}: {old or 'absent'} -> {new or 'absent'}.",
                    severity="medium" if new == "failed" else "info",
                    before={"scanner": scanner, "status": old},
                    after={"scanner": scanner, "status": new},
                )
            )
    return items


def _version_drift(current: Scan, reference: Scan | BaselineSnapshot) -> list[DriftItem]:
    if isinstance(reference, Scan):
        before_scanners = {run.scanner: run.version for run in reference.scanner_runs}
        before_rules = {"NOPE rules": "local"}
        before_model = reference.ai_review.model
        before_rag = "phase-6-v1"
    else:
        before_scanners = reference.scanner_versions
        before_rules = reference.rule_versions
        before_model = reference.model_version
        before_rag = reference.rag_version
    after_scanners = {run.scanner: run.version for run in current.scanner_runs}
    after_rules = {"NOPE rules": "local"}
    after_model = current.ai_review.model
    after_rag = "phase-6-v1"

    items: list[DriftItem] = []
    for scanner in sorted(set(before_scanners) | set(after_scanners)):
        old = before_scanners.get(scanner)
        new = after_scanners.get(scanner)
        if old != new:
            items.append(
                DriftItem(
                    type="scanner_version_change",
                    message=f"Scanner version changed for {scanner}: {old or 'absent'} -> {new or 'absent'}.",
                    severity="info",
                    before={"scanner": scanner, "version": old},
                    after={"scanner": scanner, "version": new},
                )
            )
    for rule_source in sorted(set(before_rules) | set(after_rules)):
        old = before_rules.get(rule_source)
        new = after_rules.get(rule_source)
        if old != new:
            items.append(
                DriftItem(
                    type="rule_version_change",
                    message=f"Rule version changed for {rule_source}: {old or 'absent'} -> {new or 'absent'}.",
                    severity="info",
                    before={"rule_source": rule_source, "version": old},
                    after={"rule_source": rule_source, "version": new},
                )
            )
    if before_model != after_model:
        items.append(
            DriftItem(
                type="model_version_change",
                message=f"Model version changed: {before_model or 'none'} -> {after_model or 'none'}.",
                severity="info",
                before={"model_version": before_model},
                after={"model_version": after_model},
            )
        )
    if before_rag != after_rag:
        items.append(
            DriftItem(
                type="rag_version_change",
                message=f"RAG version changed: {before_rag or 'none'} -> {after_rag or 'none'}.",
                severity="info",
                before={"rag_version": before_rag},
                after={"rag_version": after_rag},
            )
        )
    return items


def _stack_drift(current: Scan, reference: Scan | BaselineSnapshot) -> list[DriftItem]:
    current_stack = {item.technology for item in current.stack}
    reference_stack = {item.technology for item in reference.stack} if isinstance(reference, Scan) else set(reference.stack)
    return [
        DriftItem(type="recurring_finding", message=f"Stack changed: {technology}.", severity="info", after={"technology": technology})
        for technology in sorted(current_stack ^ reference_stack)
    ]


def _domain_drift(current: Scan, reference: Scan | BaselineSnapshot) -> list[DriftItem]:
    before_routes = {item.route for item in reference.attack_surface} if isinstance(reference, Scan) else set(reference.routes)
    after_routes = {item.route for item in current.attack_surface}
    items: list[DriftItem] = []
    items.extend(DriftItem(type="new_route", message=f"New route: {route}.", severity="info", after={"route": route}) for route in sorted(after_routes - before_routes))
    items.extend(DriftItem(type="removed_route", message=f"Removed route: {route}.", severity="info", before={"route": route}) for route in sorted(before_routes - after_routes))
    for finding in current.findings:
        title = f"{finding.title} {finding.category}".lower()
        if finding.package and finding.fingerprint not in _reference_findings(reference):
            items.append(DriftItem(type="new_dependency", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"New dependency finding: {finding.package}.", after=_finding_summary(finding)))
        if finding.cve and finding.fingerprint not in _reference_findings(reference):
            items.append(DriftItem(type="new_cve", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"New CVE: {finding.cve}.", after=_finding_summary(finding)))
        if "secret" in title and finding.fingerprint not in _reference_findings(reference):
            items.append(DriftItem(type="new_secret", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"New secret finding: {finding.title}.", after=_finding_summary(finding)))
        if "rls" in title or "supabase" in title:
            items.append(DriftItem(type="rls_policy_change", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"RLS/Supabase drift signal: {finding.title}.", after=_finding_summary(finding)))
        if "cors" in title:
            items.append(DriftItem(type="weaker_cors", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"CORS drift signal: {finding.title}.", after=_finding_summary(finding)))
        if "header" in title:
            items.append(DriftItem(type="weaker_headers", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"Header drift signal: {finding.title}.", after=_finding_summary(finding)))
        if "tracker" in title:
            items.append(DriftItem(type="new_tracker", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"Tracker drift signal: {finding.title}.", after=_finding_summary(finding)))
        if "public" in title or "bucket" in title or "source map" in title:
            items.append(DriftItem(type="new_public_asset", fingerprint=finding.fingerprint, severity=finding.severity.value, message=f"Public asset drift signal: {finding.title}.", after=_finding_summary(finding)))
    return _dedupe_events(items)


def _incremental_scope(current: Scan, reference: Scan | BaselineSnapshot, new: list[Finding], fixed: list[dict[str, Any]], drift: list[DriftItem]) -> dict[str, Any]:
    changed_files = sorted(
        {
            *(finding.affected_file for finding in new if finding.affected_file),
            *(str(item.get("file")) for item in fixed if item.get("file")),
        }
    )
    affected_graph_nodes = [
        node.model_dump(mode="json")
        for node in current.code_graph.nodes
        if node.file in changed_files
    ]
    categories = Counter(finding.category for finding in new)
    relevant_scanners = sorted({source for finding in new for source in finding.scanner_sources} or {run.scanner for run in current.scanner_runs})
    return {
        "mode": "conservative",
        "changed_files": changed_files,
        "affected_graph_nodes": affected_graph_nodes,
        "relevant_scanners": relevant_scanners,
        "finding_categories": dict(categories),
        "requires_full_scan": bool(drift),
        "note": "Incremental scope is advisory; NOPE keeps full-scan verification as the authoritative comparison path.",
    }


def _dedupe_events(items: list[DriftItem]) -> list[DriftItem]:
    seen: set[tuple[str, str | None, str]] = set()
    result: list[DriftItem] = []
    for item in items:
        key = (item.type, item.fingerprint, item.message)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
