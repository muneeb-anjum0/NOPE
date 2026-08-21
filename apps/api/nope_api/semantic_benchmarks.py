from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from nope_api.finding_quality import apply_finding_quality_gate
from nope_api.models import Confidence, Evidence, Finding, Severity


def run_semantic_corpus(root: Path) -> dict[str, object]:
    manifest = json.loads((root / "semantic-manifest.json").read_text(encoding="utf-8"))
    totals = Counter()
    results = []
    for item in manifest["cases"]:
        case_root = root / item["repository"]
        finding = Finding(
            scanner=item.get("scanner", "NOPE Rules v2"),
            original_rule_id=item.get("rule", "NOPE-SEMANTIC"),
            fingerprint=item["id"],
            original_fingerprint=item["id"],
            title=item["title"],
            description=item["title"],
            severity=Severity(item.get("severity", "high")),
            confidence=Confidence.high,
            category=item.get("category", "Staging"),
            affected_file=item["file"],
            affected_route=item.get("route"),
            remediation="Review semantic proof.",
            verification_state="rules_v2_promoted",
            evidence=[
                Evidence(
                    source=item.get("scanner", "NOPE Rules v2"),
                    file=item["file"],
                    message=item["title"],
                )
            ],
        )
        confirmed, observations, metrics = apply_finding_quality_gate([finding], case_root)
        predicted = bool(confirmed)
        expected = bool(item["expected_confirmed"])
        totals.update(
            {
                "tp": int(predicted and expected),
                "fp": int(predicted and not expected),
                "fn": int(not predicted and expected),
                "tn": int(not predicted and not expected),
            }
        )
        result = observations[0]
        results.append(
            {
                "id": item["id"],
                "expected": expected,
                "confirmed": predicted,
                "disposition": result.disposition.value,
                "reason": result.disposition_reason_codes[0],
                "context": [value.value for value in result.execution_contexts],
                "reachability": result.reachability.value,
                "raw_observations": metrics["raw_observation_count"],
            }
        )
    tp, fp, fn, tn = (totals[key] for key in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {
        "cases": results,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_discovery_rate": fp / (tp + fp) if tp + fp else 0.0,
    }
