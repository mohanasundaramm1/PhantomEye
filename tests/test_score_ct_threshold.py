import json

from ct.score.score_ct_with_latest import choose_threshold, model_version_tag


# ---------- new-format lookup: metrics[<primary_name>].threshold_at_1pct_fpr ----------

def test_reads_threshold_from_primary_model_metrics():
    meta = {
        "metrics": {
            "lgbm_full": {
                "roc_auc": 0.99,
                "pr_auc": 0.99,
                "recall_at_1pct": 0.93,
                "threshold_at_1pct_fpr": 0.7321,
            },
            "logreg_full": {
                "roc_auc": 0.94,
                "pr_auc": 0.98,
                "recall_at_1pct": 0.21,
                "threshold_at_1pct_fpr": 0.5555,
            },
        }
    }
    assert choose_threshold(meta, primary_name="lgbm_full") == 0.7321
    assert choose_threshold(meta, primary_name="logreg_full") == 0.5555


def test_uses_correct_model_when_lgbm_is_primary():
    # LightGBM available -> primary_name="lgbm_full" per score_ct_with_latest.main();
    # must not accidentally pick up logreg_full's threshold instead.
    meta = {
        "metrics": {
            "lgbm_full": {"threshold_at_1pct_fpr": 0.81},
            "logreg_full": {"threshold_at_1pct_fpr": 0.42},
        }
    }
    assert choose_threshold(meta, primary_name="lgbm_full") == 0.81


def test_uses_correct_model_when_logreg_is_primary():
    # LightGBM unavailable -> primary_name="logreg_full" per score_ct_with_latest.main().
    meta = {
        "metrics": {
            "lgbm_full": {"threshold_at_1pct_fpr": 0.81},
            "logreg_full": {"threshold_at_1pct_fpr": 0.42},
        }
    }
    assert choose_threshold(meta, primary_name="logreg_full") == 0.42


def test_string_threshold_value_is_coerced_to_float():
    meta = {"metrics": {"lgbm_full": {"threshold_at_1pct_fpr": "0.65"}}}
    thr = choose_threshold(meta, primary_name="lgbm_full")
    assert thr == 0.65
    assert isinstance(thr, float)


# ---------- fallback: 0.90 hardcoded default ----------

def test_falls_back_to_default_when_meta_is_none():
    assert choose_threshold(None, primary_name="lgbm_full") == 0.90


def test_falls_back_to_default_when_meta_is_empty():
    assert choose_threshold({}, primary_name="lgbm_full") == 0.90


def test_falls_back_to_default_when_primary_name_missing():
    meta = {"metrics": {"lgbm_full": {"threshold_at_1pct_fpr": 0.81}}}
    assert choose_threshold(meta, primary_name=None) == 0.90


def test_falls_back_to_default_when_primary_model_not_in_metrics():
    meta = {"metrics": {"logreg_full": {"threshold_at_1pct_fpr": 0.42}}}
    assert choose_threshold(meta, primary_name="lgbm_full") == 0.90


def test_falls_back_to_default_for_old_meta_json_without_threshold_key():
    # Pre-fix meta.json shape: only roc_auc / pr_auc / recall_at_1pct, no
    # threshold_at_1pct_fpr anywhere. This is the format every meta.json
    # written before this fix actually has on disk.
    old_meta = {
        "created_utc": "2026-02-15T00:19:16.233505+00:00",
        "metrics": {
            "logreg_lex": {
                "roc_auc": 0.923,
                "pr_auc": 0.975,
                "recall_at_1pct": 0.242,
            },
            "logreg_full": {
                "roc_auc": 0.946,
                "pr_auc": 0.981,
                "recall_at_1pct": 0.212,
            },
            "lgbm_lex": {
                "roc_auc": 0.975,
                "pr_auc": 0.994,
                "recall_at_1pct": 0.858,
            },
            "lgbm_full": {
                "roc_auc": 0.991,
                "pr_auc": 0.998,
                "recall_at_1pct": 0.927,
            },
        },
        "feature_shapes": {"X_lex": [52125, 4106], "X_full": [52125, 4371]},
    }
    assert choose_threshold(old_meta, primary_name="lgbm_full") == 0.90
    assert choose_threshold(old_meta, primary_name="logreg_full") == 0.90


def test_falls_back_to_default_against_real_on_disk_meta_json(tmp_path):
    # Regression guard: exercise choose_threshold against an actual meta.json
    # payload captured from ml/models/registry/ct_risk_meta_latest.json
    # (pre-fix format, written 2026-02-15) to make sure the fallback path
    # doesn't crash on real on-disk data and correctly returns 0.90.
    real_pre_fix_meta_json = """
    {
      "created_utc": "2026-02-15T00:19:16.233505+00:00",
      "n_rows": 52125,
      "n_pos": 41343,
      "n_neg": 10782,
      "metrics": {
        "logreg_lex": {
          "roc_auc": 0.92301323885403,
          "pr_auc": 0.9751224206590027,
          "recall_at_1pct": 0.24245356037151702
        },
        "logreg_full": {
          "roc_auc": 0.9455651389284432,
          "pr_auc": 0.9805714205136156,
          "recall_at_1pct": 0.21217105263157895
        },
        "lgbm_lex": {
          "roc_auc": 0.9751939434410339,
          "pr_auc": 0.9938021955417249,
          "recall_at_1pct": 0.8584558823529411
        },
        "lgbm_full": {
          "roc_auc": 0.990641378466895,
          "pr_auc": 0.9976534365009367,
          "recall_at_1pct": 0.927438080495356
        }
      },
      "feature_shapes": {
        "X_lex": [52125, 4106],
        "X_full": [52125, 4371]
      }
    }
    """
    meta_path = tmp_path / "ct_risk_meta_latest.json"
    meta_path.write_text(real_pre_fix_meta_json)
    with open(meta_path) as f:
        meta = json.load(f)

    thr = choose_threshold(meta, primary_name="lgbm_full")
    assert thr == 0.90


def test_legacy_top_level_key_still_honoured_for_forward_compat():
    # Some hypothetical alternate meta shape stores the threshold at the
    # top level instead of nested under metrics[<model_name>]; the old
    # (pre-fix) lookup keys should still work as a secondary fallback.
    meta = {"threshold_at_1pct_fpr": 0.77}
    assert choose_threshold(meta, primary_name="lgbm_full") == 0.77

    meta2 = {"fpr_1pct_threshold": 0.66}
    assert choose_threshold(meta2, primary_name="lgbm_full") == 0.66


# ---------- model_version_tag: distinguishing scores by which training run made them ----------

def test_model_version_tag_combines_name_and_created_utc():
    meta = {"created_utc": "2026-07-08T03:50:42.434713+00:00"}
    assert model_version_tag("lgbm_full", meta) == "lgbm_full@20260708T035042Z"


def test_model_version_tag_handles_z_suffix_iso_format():
    meta = {"created_utc": "2026-07-08T03:50:42Z"}
    assert model_version_tag("lgbm_full", meta) == "lgbm_full@20260708T035042Z"


def test_model_version_tag_fits_ctobservation_model_used_column():
    # CtObservation.model_used is String(32); the longest primary_name
    # ("logreg_full", 11 chars) + "@" + 16-char timestamp = 28 chars, must
    # never exceed 32 regardless of which model produced it.
    meta = {"created_utc": "2026-07-08T03:50:42.434713+00:00"}
    tag = model_version_tag("logreg_full", meta)
    assert len(tag) <= 32


def test_model_version_tag_falls_back_to_bare_name_when_meta_missing():
    assert model_version_tag("lgbm_full", None) == "lgbm_full"
    assert model_version_tag("lgbm_full", {}) == "lgbm_full"


def test_model_version_tag_falls_back_to_bare_name_when_created_utc_malformed():
    meta = {"created_utc": "not-a-real-timestamp"}
    assert model_version_tag("lgbm_full", meta) == "lgbm_full"
