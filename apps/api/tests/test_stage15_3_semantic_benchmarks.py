from pathlib import Path

from nope_api.semantic_benchmarks import run_semantic_corpus


def test_semantic_noise_and_vulnerable_pairs_preserve_precision_and_recall():
    root = Path(__file__).resolve().parents[3] / "benchmarks" / "semantic-context"
    result = run_semantic_corpus(root)
    assert result["true_negatives"] >= 20
    assert result["true_positives"] >= 4
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["false_discovery_rate"] == 0.0
    assert all(case["raw_observations"] == 1 for case in result["cases"])
