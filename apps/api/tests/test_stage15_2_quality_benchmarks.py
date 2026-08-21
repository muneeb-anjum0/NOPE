from pathlib import Path

from nope_api.quality_benchmarks import run_quality_corpus


def test_false_positive_corpus_preserves_recall_and_rejects_noise():
    root = Path(__file__).resolve().parents[3] / "benchmarks" / "quality-corpora"
    result = run_quality_corpus(root)

    assert len(result["cases"]) >= 5
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["false_positive_rate"] == 0.0
    assert result["false_discovery_rate"] == 0.0
    assert all(case["disposition_matches"] == case["expected_count"] for case in result["cases"])
