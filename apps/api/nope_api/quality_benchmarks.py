from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from nope_api.finding_quality import apply_finding_quality_gate
from nope_api.models import Confidence, Evidence, Finding, Severity


def run_quality_corpus(root: Path) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    totals = Counter()
    for manifest_path in sorted(root.rglob("finding-quality-manifest.json")):
        case_root = manifest_path.parent
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        observations: list[Finding] = []
        decisions: list[dict[str, object]] = []
        expected: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(manifest.get("observations", [])):
            observation = _observation(item, index)
            observations.append(observation)
            expected[observation.original_fingerprint or observation.fingerprint] = item
            if item.get("validation_state"):
                decisions.append({
                    "fingerprint": observation.fingerprint,
                    "state": item["validation_state"],
                    "reasons": item.get("validation_reasons", []),
                })
        confirmed, classified, metrics = apply_finding_quality_gate(observations, case_root, decisions)
        confirmed_ids = {item.original_fingerprint for item in confirmed}
        tp = fp = fn = tn = 0
        disposition_matches = 0
        for item in classified:
            original = item.original_fingerprint or item.fingerprint
            expected_item = expected[original]
            expected_positive = bool(expected_item.get("expected_confirmed"))
            predicted_positive = original in confirmed_ids
            tp += int(expected_positive and predicted_positive)
            fp += int(not expected_positive and predicted_positive)
            fn += int(expected_positive and not predicted_positive)
            tn += int(not expected_positive and not predicted_positive)
            disposition_matches += int(item.disposition.value == expected_item.get("expected_disposition"))
        totals.update({"true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn})
        cases.append({
            "name": manifest.get("name") or case_root.name,
            "path": str(case_root),
            "metrics": metrics,
            "expected_count": len(expected),
            "disposition_matches": disposition_matches,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
        })
    tp, fp, fn, tn = (totals[key] for key in ("true_positives", "false_positives", "false_negatives", "true_negatives"))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    false_discovery_rate = fp / (tp + fp) if tp + fp else 0.0
    return {
        "cases": cases,
        **dict(totals),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_discovery_rate": false_discovery_rate,
        "predicted_positive_definition": "disposition is confirmed or confirmed_with_compensating_control and is not superseded",
    }


def _observation(item: dict[str, Any], index: int) -> Finding:
    fingerprint = str(item.get("id") or f"quality-{index}")
    scanner = str(item.get("scanner") or "Unknown")
    return Finding(
        fingerprint=fingerprint,
        original_fingerprint=fingerprint,
        scanner=scanner,
        scanner_sources=[scanner],
        original_rule_id=item.get("rule"),
        title=str(item.get("title") or item.get("rule") or "Observation"),
        description=str(item.get("description") or item.get("title") or "Observation"),
        severity=Severity(str(item.get("severity") or "medium")),
        original_severity=str(item.get("upstream_severity") or item.get("severity") or "medium").upper(),
        confidence=Confidence(str(item.get("confidence") or "high")),
        category=str(item.get("category") or "Unknown"),
        affected_file=item.get("file"),
        start_line=item.get("line"),
        package=item.get("package"),
        cve=item.get("cve"),
        remediation="Review the deterministic disposition and cited evidence.",
        evidence=[Evidence(source=scanner, file=item.get("file"), line=item.get("line"), message=str(item.get("evidence") or item.get("title") or "Observation"))],
        verification_state=str(item.get("verification_state") or "unverified"),
    )
