"""Tests for ml/core/eval_benign_fpr.py -- pure logic against fake,
injectable models (no real LightGBM/joblib artifact needed). Feature
building runs for real (build_features_from_df needs only
`registered_domain`, per ml/core/features.py)."""
import numpy as np
import pandas as pd

from ml.core.eval_benign_fpr import compute_benign_fpr, load_promoted_model


class FakeLgbmModel:
    """Mimics lgb.Booster: .predict(X) -> 1D array of scores."""

    def __init__(self, scores):
        self.scores = np.asarray(scores, dtype=float)

    def predict(self, X):
        assert X.shape[0] == len(self.scores)
        return self.scores


class FakeLogregModel:
    """Mimics sklearn: .predict_proba(X) -> 2D array, positive class in col 1."""

    def __init__(self, scores):
        self.scores = np.asarray(scores, dtype=float)

    def predict_proba(self, X):
        assert X.shape[0] == len(self.scores)
        return np.column_stack([1 - self.scores, self.scores])


def _holdout(n):
    return pd.DataFrame({"registered_domain": [f"business-name-{i}.com" for i in range(n)]})


def test_compute_benign_fpr_lgbm_counts_correctly():
    model = FakeLgbmModel([0.1, 0.6, 0.99, 0.4, 0.5])
    result = compute_benign_fpr(model, "lgbm_full", _holdout(5), threshold=0.5)
    assert result["n_holdout"] == 5
    assert result["n_false_positive"] == 3  # 0.6, 0.99, 0.5 >= 0.5
    assert result["fpr"] == 0.6


def test_compute_benign_fpr_logreg_backend():
    model = FakeLogregModel([0.9, 0.1, 0.2, 0.8])
    result = compute_benign_fpr(model, "logreg_full", _holdout(4), threshold=0.5)
    assert result["n_false_positive"] == 2
    assert result["fpr"] == 0.5


def test_compute_benign_fpr_threshold_is_configurable():
    model = FakeLgbmModel([0.3, 0.5, 0.7])
    strict = compute_benign_fpr(model, "lgbm_full", _holdout(3), threshold=0.9)
    assert strict["n_false_positive"] == 0
    loose = compute_benign_fpr(model, "lgbm_full", _holdout(3), threshold=0.3)
    assert loose["n_false_positive"] == 3


def test_compute_benign_fpr_empty_holdout_returns_none_fpr():
    model = FakeLgbmModel([])
    result = compute_benign_fpr(model, "lgbm_full", _holdout(0))
    assert result["n_holdout"] == 0
    assert result["n_false_positive"] == 0
    assert result["fpr"] is None


def test_compute_benign_fpr_reports_score_percentiles():
    model = FakeLgbmModel([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    result = compute_benign_fpr(model, "lgbm_full", _holdout(10), threshold=0.5)
    assert result["score_percentiles"]["max"] == 1.0
    assert 0.0 <= result["score_percentiles"]["p50"] <= 1.0


def test_load_promoted_model_returns_none_when_nothing_exists(tmp_path):
    model, kind = load_promoted_model(
        logreg_path=str(tmp_path / "nope.joblib"),
        lgbm_path=str(tmp_path / "nope.txt"),
    )
    assert model is None
    assert kind is None
