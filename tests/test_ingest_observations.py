"""Observation ingest: projection/candidate-gate logic runs without a DB; the
upsert-in-place behavior (the W4 mutability decision) is verified against the
live app-db and skips cleanly when it isn't reachable.
"""
import datetime as dt

import pandas as pd
import pytest

from product.db import ping
from product.ingest_observations import (
    reevaluate_stage_for_enriched_members,
    rows_from_df,
    upsert_observations,
)


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


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_reevaluate_stage_matches_exact_host_event_ts_pair_not_cross_product():
    """Regression test for a precision bug caught in review: filtering by
    raw_host IN (...) AND event_ts IN (...) as two SEPARATE clauses would
    cross-match unrelated pairs (host A's raw_host with host B's event_ts),
    since raw_host/event_ts are only meaningful together (the table's actual
    unique key). Must use a composite tuple match. Verifies: a cluster whose
    only enriched member is NOT among the just-ingested keys does not get
    re-evaluated (would wrongly flip stage from "new" to "warming" if the
    cross-product bug were present), while a cluster whose member genuinely
    matches a just-ingested key IS re-evaluated."""
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation

    ev1 = dt.datetime(2026, 7, 4, 8, 0, 0, tzinfo=dt.timezone.utc)
    ev2 = dt.datetime(2026, 7, 4, 9, 0, 0, tzinfo=dt.timezone.utc)
    host_a, host_b = "zz-reeval-a.tk", "zz-reeval-b.tk"

    with SessionLocal() as s:
        try:
            # cluster A: member is host_a @ ev1, ALREADY enriched (tier1) from
            # a previous cycle -- but NOT among this call's just-ingested rows.
            obs_a = CtObservation(raw_host=host_a, registered_domain=host_a,
                                  event_ts=ev1, risk_score=0.9, enrichment_level="tier1")
            s.add(obs_a)
            s.flush()
            cluster_a = CampaignCluster(cluster_key="zz-reeval-cluster-a", target_brand="zztest",
                                        stage="new", first_seen=ev1, last_seen=ev1)
            s.add(cluster_a)
            s.flush()
            s.add(ClusterMember(cluster_id=cluster_a.id, observation_id=obs_a.id))
            s.commit()
            cid_a = cluster_a.id

            # cluster B: member is host_b @ ev2, genuinely among the just-ingested rows.
            obs_b = CtObservation(raw_host=host_b, registered_domain=host_b,
                                  event_ts=ev2, risk_score=0.9, enrichment_level="tier1")
            s.add(obs_b)
            s.flush()
            cluster_b = CampaignCluster(cluster_key="zz-reeval-cluster-b", target_brand="zztest",
                                        stage="new", first_seen=ev2, last_seen=ev2)
            s.add(cluster_b)
            s.flush()
            s.add(ClusterMember(cluster_id=cluster_b.id, observation_id=obs_b.id))
            s.commit()
            cid_b = cluster_b.id

            # Simulate an ingest batch containing host_a @ ev2 (WRONG pairing --
            # host_a's real event_ts is ev1) and host_b @ ev2 (correct pairing).
            # A buggy cross-product filter (raw_host IN (a,b) AND event_ts IN (ev2))
            # would match obs_a too, since host_a IS in the raw_host set and ev2
            # IS in the event_ts set, even though (host_a, ev2) was never a real row.
            rows = [
                {"raw_host": host_a, "event_ts": ev2, "enrichment_level": "tier1"},
                {"raw_host": host_b, "event_ts": ev2, "enrichment_level": "tier1"},
            ]
            n = reevaluate_stage_for_enriched_members(s, rows)
            assert n == 1  # only cluster B's genuine pair matched

            s.expire_all()
            a_after = s.execute(select(CampaignCluster).where(CampaignCluster.id == cid_a)).scalar_one()
            b_after = s.execute(select(CampaignCluster).where(CampaignCluster.id == cid_b)).scalar_one()
            assert a_after.stage == "new"       # untouched -- (host_a, ev2) was never real
            assert b_after.stage == "warming"   # genuinely re-evaluated
        finally:
            for cid in (cid_a, cid_b):
                s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
                s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.raw_host.in_([host_a, host_b])))
            s.commit()
