"""ct/score/rescore_ct_observations.py: observations_to_feature_df() and
_decision_reason() are pure (take plain attribute-bearing objects / values,
no DB needed). apply_rescore()'s actual write-back needs the live app-db
(skips cleanly when unreachable), same pattern as tests/test_stage_engine.py.
"""
import datetime as dt
from types import SimpleNamespace

import pytest

from ct.score.rescore_ct_observations import _decision_reason, observations_to_feature_df
from product.db import ping


def _fake_obs(**kw):
    defaults = dict(
        id=1, registered_domain="example.com", num_unique_ips=3, num_countries=2, num_asns=1,
        sample_asn="AS123", sample_isp="Some ISP", sample_country="US", registrar="Some Registrar",
        whois_status="clientTransferProhibited", whois_created=None, whois_expires=None, ti_misp_hit=0,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


# ---------- observations_to_feature_df ----------

def test_derives_age_days_and_days_to_expiry_from_whois_timestamps():
    now = dt.datetime.now(dt.timezone.utc)
    created = now - dt.timedelta(days=100)
    expires = now + dt.timedelta(days=30)
    df = observations_to_feature_df([_fake_obs(whois_created=created, whois_expires=expires)])
    row = df.iloc[0]
    assert abs(row["age_days"] - 100) < 0.01
    assert abs(row["days_to_expiry"] - 30) < 0.01
    assert row["created_isnull"] == 0
    assert row["expires_isnull"] == 0


def test_missing_whois_timestamps_default_to_zero_with_isnull_flags():
    df = observations_to_feature_df([_fake_obs(whois_created=None, whois_expires=None)])
    row = df.iloc[0]
    assert row["age_days"] == 0.0
    assert row["days_to_expiry"] == 0.0
    assert row["created_isnull"] == 1
    assert row["expires_isnull"] == 1


def test_maps_whois_status_to_status_column_for_cat_row():
    # build_features()'s cat_row() reads "status", not CtObservation's
    # native "whois_status" -- confirms the rename actually happens.
    df = observations_to_feature_df([_fake_obs(whois_status="ok")])
    assert df.iloc[0]["status"] == "ok"
    assert "whois_status" not in df.columns


def test_has_error_and_has_ipv6_default_to_zero_no_ctobservation_equivalent():
    df = observations_to_feature_df([_fake_obs()])
    row = df.iloc[0]
    assert row["has_error"] == 0
    assert row["has_ipv6"] == 0


def test_none_numeric_fields_default_to_zero_not_nan():
    df = observations_to_feature_df([_fake_obs(num_unique_ips=None, num_countries=None, num_asns=None)])
    row = df.iloc[0]
    assert row["num_unique_ips"] == 0
    assert row["num_countries"] == 0
    assert row["num_asns"] == 0


def test_preserves_ti_misp_hit_and_id_for_downstream_use():
    df = observations_to_feature_df([_fake_obs(id=42, ti_misp_hit=1)])
    assert df.iloc[0]["id"] == 42
    assert df.iloc[0]["ti_misp_hit"] == 1


# ---------- _decision_reason: mirrors score_ct_with_latest.py's main()::_reason() ----------

def test_decision_reason_misp_and_ml_when_both_hit():
    assert _decision_reason(risk_label=1, ti_misp_hit=1) == "MISP_AND_ML"


def test_decision_reason_misp_ioc_when_only_misp_hits():
    assert _decision_reason(risk_label=0, ti_misp_hit=1) == "MISP_IOC"


def test_decision_reason_ml_score_when_only_model_flags():
    assert _decision_reason(risk_label=1, ti_misp_hit=0) == "ML_SCORE"


def test_decision_reason_benign_baseline_when_neither_flags():
    assert _decision_reason(risk_label=0, ti_misp_hit=0) == "BENIGN_BASELINE"


# ---------- live write-back ----------

@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_apply_rescore_writes_new_fields_to_real_row():
    import pandas as pd
    from sqlalchemy import delete

    from ct.score.rescore_ct_observations import apply_rescore
    from product.db import SessionLocal
    from product.models import CtObservation

    with SessionLocal() as s:
        obs = CtObservation(
            raw_host="zztest-rescore.com", registered_domain="zztest-rescore.com",
            event_ts=dt.datetime.now(dt.timezone.utc), enrichment_level="tier1",
            risk_score=0.99, model_used="lgbm_full", risk_label_final=1, decision_reason="ML_SCORE",
        )
        s.add(obs)
        s.commit()
        oid = obs.id

        try:
            audit_df = pd.DataFrame.from_records([{
                "id": oid, "new_risk_score": 0.05, "new_model_used": "lgbm_full@20260708T000000Z",
                "new_risk_label_final": 0, "new_decision_reason": "BENIGN_BASELINE",
            }])
            n = apply_rescore(s, audit_df)
            assert n == 1

            refreshed = s.get(CtObservation, oid)
            assert refreshed.risk_score == 0.05
            assert refreshed.model_used == "lgbm_full@20260708T000000Z"
            assert refreshed.risk_label_final == 0
            assert refreshed.decision_reason == "BENIGN_BASELINE"
        finally:
            s.execute(delete(CtObservation).where(CtObservation.id == oid))
            s.commit()
