"""Tests for ml/core/promotion_gate.py -- pure functions, no real training."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.core.promotion_gate import (
    append_promotion_log,
    decide_promotion,
    load_champion_meta,
    primary_metric,
    verify_latest_decision,
)


def _meta(roc_auc_lgbm=None, roc_auc_logreg=None, n_pos=100, n_neg=100, used_temporal=True):
    metrics = {}
    if roc_auc_lgbm is not None:
        metrics["lgbm_full"] = {"roc_auc": roc_auc_lgbm}
    if roc_auc_logreg is not None:
        metrics["logreg_full"] = {"roc_auc": roc_auc_logreg}
    return {"metrics": metrics, "n_pos": n_pos, "n_neg": n_neg, "used_temporal_split": used_temporal}


def test_primary_metric_prefers_lgbm_over_logreg():
    m = _meta(roc_auc_lgbm=0.95, roc_auc_logreg=0.80)
    assert primary_metric(m) == ("lgbm_full", 0.95)


def test_primary_metric_falls_back_to_logreg_when_no_lgbm():
    m = _meta(roc_auc_lgbm=None, roc_auc_logreg=0.80)
    assert primary_metric(m) == ("logreg_full", 0.80)


def test_primary_metric_none_for_missing_or_malformed_meta():
    assert primary_metric(None) is None
    assert primary_metric({}) is None
    assert primary_metric({"metrics": {}}) is None
    assert primary_metric({"metrics": {"lgbm_full": {"roc_auc": "not_a_number"}}}) is None


def test_first_ever_run_promotes_with_no_champion():
    challenger = _meta(roc_auc_lgbm=0.90)
    d = decide_promotion(champion_meta=None, challenger_meta=challenger)
    assert d["promote"] is True
    assert "no existing champion" in d["reason"]


def test_rejects_challenger_below_absolute_floor():
    challenger = _meta(roc_auc_lgbm=0.50)
    d = decide_promotion(champion_meta=None, challenger_meta=challenger, min_auc_floor=0.70)
    assert d["promote"] is False
    assert "below the minimum floor" in d["reason"]


def test_rejects_regression_beyond_tolerance():
    champion = _meta(roc_auc_lgbm=0.95)
    challenger = _meta(roc_auc_lgbm=0.85)  # 0.10 worse
    d = decide_promotion(champion, challenger, max_regression_tolerance=0.02)
    assert d["promote"] is False
    assert "regresses" in d["reason"]
    assert d["champion_primary"]["roc_auc"] == 0.95
    assert d["challenger_primary"]["roc_auc"] == 0.85


def test_promotes_within_regression_tolerance():
    champion = _meta(roc_auc_lgbm=0.95)
    challenger = _meta(roc_auc_lgbm=0.94)  # 0.01 worse, within 0.02 tolerance
    d = decide_promotion(champion, challenger, max_regression_tolerance=0.02)
    assert d["promote"] is True


def test_promotes_when_challenger_improves_on_champion():
    champion = _meta(roc_auc_lgbm=0.90)
    challenger = _meta(roc_auc_lgbm=0.95)
    d = decide_promotion(champion, challenger)
    assert d["promote"] is True
    assert "delta=+0.0500" in d["reason"]


def test_rejects_degenerate_single_class_training_data():
    challenger = _meta(roc_auc_lgbm=0.95, n_pos=0, n_neg=100)
    d = decide_promotion(champion_meta=None, challenger_meta=challenger)
    assert d["promote"] is False
    assert "degenerate" in d["reason"]


def test_warns_but_does_not_block_on_non_temporal_split():
    challenger = _meta(roc_auc_lgbm=0.95, used_temporal=False)
    d = decide_promotion(champion_meta=None, challenger_meta=challenger)
    assert d["promote"] is True  # not blocked
    assert any("NOT evaluated on a genuine temporal split" in w for w in d["warnings"])


def test_no_warning_when_temporal_split_was_used():
    challenger = _meta(roc_auc_lgbm=0.95, used_temporal=True)
    d = decide_promotion(champion_meta=None, challenger_meta=challenger)
    assert d["warnings"] == []


def test_load_champion_meta_missing_file_returns_none(tmp_path):
    assert load_champion_meta(str(tmp_path)) is None


def test_load_champion_meta_reads_real_file(tmp_path):
    path = tmp_path / "ct_risk_meta_latest.json"
    path.write_text(json.dumps({"n_pos": 5}))
    m = load_champion_meta(str(tmp_path))
    assert m == {"n_pos": 5}


def test_load_champion_meta_corrupt_file_returns_none_not_raise(tmp_path):
    path = tmp_path / "ct_risk_meta_latest.json"
    path.write_text("{not valid json")
    assert load_champion_meta(str(tmp_path)) is None


def test_append_promotion_log_is_append_only_jsonl(tmp_path):
    log_path = str(tmp_path / "nested" / "promotion_log.jsonl")
    append_promotion_log({"promote": True, "reason": "first"}, log_path)
    append_promotion_log({"promote": False, "reason": "second"}, log_path)
    with open(log_path) as f:
        lines = [json.loads(l) for l in f]
    assert len(lines) == 2
    assert lines[0]["reason"] == "first"
    assert lines[1]["reason"] == "second"


def test_decide_promotion_never_raises_on_champion_meta_missing_metrics_key():
    # champion_meta present but malformed (no "metrics" key at all) -- must
    # be treated as "no usable champion", not crash.
    challenger = _meta(roc_auc_lgbm=0.90)
    d = decide_promotion(champion_meta={"n_pos": 1}, challenger_meta=challenger)
    assert d["promote"] is True
    assert d["champion_primary"] is None


# ---------------- verify_latest_decision: "did the gate actually run" ----------------

def _write_log_line(log_path, **overrides):
    entry = {"promote": True, "reason": "PROMOTED: test",
            "checked_utc": datetime.now(timezone.utc).isoformat()}
    entry.update(overrides)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def test_verify_latest_decision_missing_log_fails():
    ok, msg = verify_latest_decision("/nonexistent/path/promotion_log.jsonl")
    assert ok is False
    assert "NO promotion log" in msg


def test_verify_latest_decision_empty_log_fails(tmp_path):
    log_path = str(tmp_path / "promotion_log.jsonl")
    open(log_path, "w").close()
    ok, msg = verify_latest_decision(log_path)
    assert ok is False
    assert "empty" in msg


def test_verify_latest_decision_recent_valid_entry_passes_regardless_of_promote_value(tmp_path):
    log_path = str(tmp_path / "promotion_log.jsonl")
    _write_log_line(log_path, promote=False, reason="REJECTED: regression")  # a legitimate reject
    ok, msg = verify_latest_decision(log_path)
    assert ok is True  # a rejection is healthy behavior, not a gate failure
    assert "REJECTED" in msg


def test_verify_latest_decision_stale_entry_fails(tmp_path):
    log_path = str(tmp_path / "promotion_log.jsonl")
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    _write_log_line(log_path, checked_utc=stale_ts)
    ok, msg = verify_latest_decision(log_path, max_age_hours=24.0)
    assert ok is False
    assert "old" in msg


def test_verify_latest_decision_malformed_json_fails(tmp_path):
    log_path = str(tmp_path / "promotion_log.jsonl")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as f:
        f.write("{not valid json\n")
    ok, msg = verify_latest_decision(log_path)
    assert ok is False
    assert "could not parse" in msg


def test_verify_latest_decision_uses_only_the_last_line(tmp_path):
    """A stale first entry followed by a fresh one must pass -- only the
    LATEST decision matters."""
    log_path = str(tmp_path / "promotion_log.jsonl")
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    _write_log_line(log_path, checked_utc=stale_ts)
    _write_log_line(log_path)  # fresh
    ok, msg = verify_latest_decision(log_path, max_age_hours=24.0)
    assert ok is True
