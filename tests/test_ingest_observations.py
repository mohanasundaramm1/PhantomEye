"""Observation ingest: projection/candidate-gate logic runs without a DB; the
upsert-in-place behavior (the W4 mutability decision) is verified against the
live app-db and skips cleanly when it isn't reachable.
"""
import datetime as dt

import pandas as pd
import pytest

from product.db import ping
from product.ingest_observations import rows_from_df, upsert_observations


# ---------- pure projection + candidate gate (no DB) ----------

def _df(records):
    return pd.DataFrame(records)


def test_candidate_gate_keeps_high_risk_misp_and_label():
    df = _df([
        {"domain_sample": "a.com", "event_ts": "2026-07-03T00:00:00Z", "risk_score": 0.9},
        {"domain_sample": "b.com", "event_ts": "2026-07-03T00:00:00Z", "risk_score": 0.1,
         "risk_label_final": 0, "ti_misp_hit": 0},
        {"domain_sample": "c.com", "event_ts": "2026-07-03T00:00:00Z", "risk_score": 0.1, "ti_misp_hit": 1},
        {"domain_sample": "d.com", "event_ts": "2026-07-03T00:00:00Z", "risk_score": 0.1, "risk_label_final": 1},
    ])
    rows, skipped = rows_from_df(df, "test.parquet", min_risk=0.5)
    hosts = {r["raw_host"] for r in rows}
    assert hosts == {"a.com", "c.com", "d.com"}   # b filtered out
    assert skipped == 0


def test_rows_without_key_are_skipped_not_ingested():
    df = _df([
        {"domain_sample": "a.com", "event_ts": None, "risk_score": 0.9},   # no event_ts
        {"domain_sample": None, "registered_domain": None, "event_ts": "2026-07-03T00:00:00Z", "risk_score": 0.9},
    ])
    rows, skipped = rows_from_df(df, "test.parquet", min_risk=0.5)
    assert rows == []
    assert skipped == 2


# ---------- live upsert-in-place (W4) ----------

@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_late_enrichment_upserts_in_place_without_duplicating():
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CtObservation

    host = "unit-test-upsert.example.test"
    ev = dt.datetime(2026, 7, 3, 12, 0, 0, tzinfo=dt.timezone.utc)

    def _row(registrar):
        return {"raw_host": host, "event_ts": ev, "registered_domain": host,
                "risk_score": 0.9, "registrar": registrar}

    def read(s):
        # expire_all so we read committed DB state, not the session's cached
        # objects (the session uses expire_on_commit=False).
        s.expire_all()
        return s.execute(select(CtObservation).where(CtObservation.raw_host == host)).scalars().all()

    with SessionLocal() as s:
        try:
            # 1) hot pass: no registrar yet
            upsert_observations(s, [_row(None)])
            got = read(s)
            assert len(got) == 1 and got[0].registrar is None

            # 2) cold backfill lands WHOIS: same key updates in place, no duplicate
            upsert_observations(s, [_row("MarkMonitor Inc.")])
            got = read(s)
            assert len(got) == 1                          # upsert, not a second row
            assert got[0].registrar == "MarkMonitor Inc."

            # 3) a later hot pass with null registrar must NOT wipe it (coalesce)
            upsert_observations(s, [_row(None)])
            got = read(s)
            assert len(got) == 1
            assert got[0].registrar == "MarkMonitor Inc."
        finally:
            s.execute(delete(CtObservation).where(CtObservation.raw_host == host))
            s.commit()
