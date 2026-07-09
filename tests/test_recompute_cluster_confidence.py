"""product/recompute_cluster_confidence.py: needs the live app-db (skips
cleanly when unreachable), same pattern as tests/test_stage_engine.py.
"""
import datetime as dt

import pytest

from product.db import ping


def _cluster(cluster_key, confidence_score):
    from product.models import CampaignCluster
    now = dt.datetime.now(dt.timezone.utc)
    return CampaignCluster(cluster_key=cluster_key, target_brand="apple", stage="warming",
                           confidence_score=confidence_score, first_seen=now, last_seen=now)


def _obs(raw_host, risk_score):
    from product.models import CtObservation
    return CtObservation(raw_host=raw_host, registered_domain=raw_host,
                         event_ts=dt.datetime.now(dt.timezone.utc), enrichment_level="tier1",
                         risk_score=risk_score)


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_compute_deltas_flags_stale_confidence_and_skips_up_to_date():
    from sqlalchemy import delete

    from product.assemble_campaigns import _confidence
    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation
    from product.recompute_cluster_confidence import compute_deltas

    with SessionLocal() as s:
        # stale: confidence_score (0.99) doesn't match what current risk_score (0.1) implies
        stale = _cluster("zztest-confidence-stale", confidence_score=0.99)
        # up to date: confidence_score already matches _confidence(0.1, 1)
        correct_value = _confidence(0.1, 1)
        up_to_date = _cluster("zztest-confidence-current", confidence_score=correct_value)
        s.add_all([stale, up_to_date])
        s.flush()

        obs1 = _obs("zztest-confidence-stale.com", risk_score=0.1)
        obs2 = _obs("zztest-confidence-current.com", risk_score=0.1)
        s.add_all([obs1, obs2])
        s.flush()
        s.add_all([
            ClusterMember(cluster_id=stale.id, observation_id=obs1.id),
            ClusterMember(cluster_id=up_to_date.id, observation_id=obs2.id),
        ])
        s.commit()

        cluster_ids = [stale.id, up_to_date.id]
        obs_ids = [obs1.id, obs2.id]
        try:
            deltas = compute_deltas(s, cluster_ids=cluster_ids)
            by_id = {d["cluster_id"]: d for d in deltas}
            assert stale.id in by_id
            assert abs(by_id[stale.id]["new_confidence"] - correct_value) < 1e-9
            assert up_to_date.id not in by_id  # already correct -- must not appear
        finally:
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id.in_(cluster_ids)))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id.in_(cluster_ids)))
            s.execute(delete(CtObservation).where(CtObservation.id.in_(obs_ids)))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_apply_deltas_writes_new_confidence_to_real_row():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation
    from product.recompute_cluster_confidence import apply_deltas, compute_deltas

    with SessionLocal() as s:
        cluster = _cluster("zztest-confidence-apply", confidence_score=0.99)
        s.add(cluster)
        s.flush()
        obs = _obs("zztest-confidence-apply.com", risk_score=0.2)
        s.add(obs)
        s.flush()
        s.add(ClusterMember(cluster_id=cluster.id, observation_id=obs.id))
        s.commit()
        cid, oid = cluster.id, obs.id

        try:
            deltas = compute_deltas(s, cluster_ids=[cid])
            assert len(deltas) == 1
            n = apply_deltas(s, deltas)
            assert n == 1

            refreshed = s.get(CampaignCluster, cid)
            assert refreshed.confidence_score == deltas[0]["new_confidence"]
            assert refreshed.confidence_score != 0.99
        finally:
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.id == oid))
            s.commit()
