"""Serving-side WHOIS numeric derivation must match ml/core/train_model.py.

Regression guard for the bug where every serving path (live API, batch
scorer, rescore) zero-filled age_days/days_to_expiry/created_isnull/...
instead of deriving them from the raw WHOIS record -- making every domain
look "registered today, date known" to the model (google.com scored ~0.49).
"""
import pandas as pd
import pytest

from ml.core.features import (
    WHOIS_NUM_COLS,
    build_features,
    derive_whois_numeric,
    prepare_whois_columns,
)

NOW = pd.Timestamp("2026-09-23T00:00:00Z")


def test_no_whois_record_is_all_zero_like_training_left_merge():
    # train_model.py left-merges WHOIS; a domain with no row gets NaN -> fillna(0)
    out = derive_whois_numeric({"registered_domain": "x.com"}, NOW)
    assert out == {c: 0.0 for c in WHOIS_NUM_COLS}


def test_dates_present_produce_real_age_and_expiry():
    out = derive_whois_numeric({
        "registrar": "MarkMonitor Inc.",
        "whois_created": "1997-09-15T04:00:00Z",
        "whois_expires": "2028-09-14T04:00:00Z",
    }, NOW)
    assert out["age_days"] > 10_000
    assert out["days_to_expiry"] > 0
    assert out["created_isnull"] == 0.0
    assert out["expires_isnull"] == 0.0
    assert out["has_error"] == 0.0


def test_record_without_dates_flags_isnull_like_training():
    # WHOIS answered (e.g. not_found) but no dates: training sets isnull=1
    out = derive_whois_numeric({"whois_status": "not_found", "whois_created": None}, NOW)
    assert out["created_isnull"] == 1.0
    assert out["expires_isnull"] == 1.0
    assert out["age_days"] == 0.0


def test_error_sets_has_error():
    out = derive_whois_numeric({"whois_error": "timeout"}, NOW)
    assert out["has_error"] == 1.0


def test_raw_fields_win_over_prezero_filled_columns():
    # Upstream steps zero-fill WHOIS_NUM_COLS; trusting those zeros would
    # silently preserve the original bug.
    rec = {c: 0.0 for c in WHOIS_NUM_COLS}
    rec.update({"registrar": "R", "whois_created": "2000-01-01T00:00:00Z"})
    out = derive_whois_numeric(rec, NOW)
    assert out["age_days"] > 9_000


def test_whois_created_none_falls_back_to_created_key():
    # enrich_item() always writes whois_created (often None)
    out = derive_whois_numeric({"whois_created": None, "created": "2010-01-01T00:00:00Z"}, NOW)
    assert out["age_days"] > 5_000


def test_prepare_whois_columns_derives_and_aliases_status():
    df = pd.DataFrame([
        {"registered_domain": "old.com", "whois_status": "ok",
         "whois_created": "2001-01-01T00:00:00Z", "age_days": 0.0},
        {"registered_domain": "none.com"},
    ])
    prepare_whois_columns(df, NOW)
    assert df.loc[0, "age_days"] > 9_000
    assert df.loc[0, "status"] == "ok"          # cat_row() reads "status"
    assert df.loc[1, "age_days"] == 0.0
    assert df.loc[1, "created_isnull"] == 0.0   # no record -> training says 0


def test_live_builder_carries_derived_age_into_vector():
    X_old = build_features("old.com", {"registrar": "R", "whois_created": "1999-01-01T00:00:00Z"})
    X_new = build_features("old.com", {})
    # last 5 columns are WHOIS_NUM_COLS; age_days is the first of them
    assert X_old.toarray()[0, -5] > 9_000
    assert X_new.toarray()[0, -5] == 0.0
