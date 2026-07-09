"""Precision@K: pure computation over an in-memory DataFrame, no files/DB needed."""
import pandas as pd

from ml.core.eval_precision_at_k import precision_at_k


def _df(rows):
    return pd.DataFrame(rows)


def test_precision_at_k_perfect_ranking():
    # top 2 by score are both hits
    df = _df([
        {"risk_score": 0.9, "ti_misp_hit": 1},
        {"risk_score": 0.8, "ti_misp_hit": 1},
        {"risk_score": 0.1, "ti_misp_hit": 0},
    ])
    r = precision_at_k(df, k=2)
    assert r == {"k": 2, "precision": 1.0, "n_evaluated": 2, "n_hits": 2}


def test_precision_at_k_zero_hits_in_top_k():
    df = _df([
        {"risk_score": 0.9, "ti_misp_hit": 0},
        {"risk_score": 0.8, "ti_misp_hit": 0},
        {"risk_score": 0.1, "ti_misp_hit": 1},  # hit, but ranked below top-2
    ])
    r = precision_at_k(df, k=2)
    assert r["precision"] == 0.0
    assert r["n_hits"] == 0


def test_precision_at_k_missing_label_column_treated_as_no_hits():
    df = _df([{"risk_score": 0.9}, {"risk_score": 0.5}])
    r = precision_at_k(df, k=2)
    assert r["precision"] == 0.0
    assert r["n_evaluated"] == 2


def test_precision_at_k_nan_label_treated_as_not_a_hit_not_dropped():
    df = _df([
        {"risk_score": 0.9, "ti_misp_hit": None},
        {"risk_score": 0.8, "ti_misp_hit": 1},
    ])
    r = precision_at_k(df, k=2)
    assert r["n_evaluated"] == 2  # both rows counted, NaN row not dropped
    assert r["n_hits"] == 1


def test_precision_at_k_fewer_rows_than_k_uses_all_available():
    df = _df([{"risk_score": 0.9, "ti_misp_hit": 1}])
    r = precision_at_k(df, k=10)
    assert r["n_evaluated"] == 1
    assert r["precision"] == 1.0


def test_precision_at_k_empty_dataframe():
    r = precision_at_k(pd.DataFrame(), k=10)
    assert r["precision"] is None
    assert r["n_evaluated"] == 0
