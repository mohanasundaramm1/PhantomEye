"""product/stage_engine.py: evaluate_stage() is pure and runs without a DB.
apply_stage_transition()'s row-locking is verified against the live app-db
(skips cleanly when unreachable) with the exact concurrent-write race the
architecture review identified: two sessions computing different stages for
the same cluster at the same time must not lose an update.
"""
import datetime as dt

import pytest

from product.db import ping
from product.models import CtObservation
from product.stage_engine import TERMINAL_STAGES, evaluate_stage


def _obs(**kw):
    defaults = dict(raw_host="x.com", registered_domain="x.com",
                     enrichment_level="tier0", ti_misp_hit=0)
    defaults.update(kw)
    return CtObservation(**defaults)


class _Cluster:
    """Minimal stand-in -- evaluate_stage() only reads attributes off cluster,
    never mutates it, so a plain object (no DB) is enough for the pure tests."""
    def __init__(self, stage="new"):
        self.stage = stage


# ---------- pure evaluate_stage() ----------

def test_new_when_no_enrichment_and_no_disposition():
    stage, reason = evaluate_stage(_Cluster(), [_obs()], disposition=None)
    assert stage == "new"

def test_warming_when_member_has_tier1_enrichment():
    stage, _ = evaluate_stage(_Cluster(), [_obs(enrichment_level="tier1")], disposition=None)
    assert stage == "warming"

def test_active_when_content_probe_evidence_present():
    stage, reason = evaluate_stage(
        _Cluster(), [_obs(enrichment_level="tier1")], disposition=None,
        evidence=[{"event_type": "content_probe_result", "detail": {"http_status": 200}}],
    )
    assert stage == "active"
    assert "probe" in reason

def test_confirmed_on_misp_hit_overrides_everything_automatic():
    stage, reason = evaluate_stage(_Cluster(), [_obs(ti_misp_hit=1)], disposition=None)
    assert stage == "confirmed"

def test_suppressed_on_suppression_match_evidence():
    stage, _ = evaluate_stage(
        _Cluster(), [_obs()], disposition=None,
        evidence=[{"event_type": "suppression_match"}],
    )
    assert stage == "suppressed"

def test_disposition_confirmed_short_circuits_regardless_of_members():
    # Even a bare CT-only observation (no enrichment) gets confirmed if an
    # analyst says so -- disposition is authoritative.
    stage, reason = evaluate_stage(_Cluster(), [_obs()], disposition={"verdict": "confirmed"})
    assert stage == "confirmed"
    assert "disposition" in reason

def test_disposition_benign_resets_to_new():
    stage, _ = evaluate_stage(_Cluster(), [_obs(ti_misp_hit=1)], disposition={"verdict": "benign"})
    assert stage == "new"

def test_terminal_stages_are_exactly_confirmed_and_suppressed():
    assert TERMINAL_STAGES == {"confirmed", "suppressed"}


# ---------- live concurrency + idempotency (apply_stage_transition) ----------

@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_apply_stage_transition_is_idempotent_no_duplicate_evidence():
    from sqlalchemy import delete, func, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, EvidenceEvent
    from product.stage_engine import apply_stage_transition

    with SessionLocal() as s:
        cluster = CampaignCluster(cluster_key="test-idempotent-stage-key", target_brand="zztest",
                                  stage="new", first_seen=dt.datetime.now(dt.timezone.utc),
                                  last_seen=dt.datetime.now(dt.timezone.utc))
        s.add(cluster)
        s.flush()
        obs = CtObservation(raw_host="zztest-idempotent.tk", registered_domain="zztest-idempotent.tk",
                            event_ts=dt.datetime.now(dt.timezone.utc), enrichment_level="tier1")
        s.add(obs)
        s.flush()
        s.add(ClusterMember(cluster_id=cluster.id, observation_id=obs.id))
        s.commit()
        cid = cluster.id
        try:
            r1 = apply_stage_transition(s, cid)
            assert r1["changed"] is True and r1["new_stage"] == "warming"
            r2 = apply_stage_transition(s, cid)  # re-run with identical inputs
            assert r2["changed"] is False  # no-op: already at/past this stage

            n_events = s.execute(
                select(func.count()).select_from(EvidenceEvent).where(EvidenceEvent.cluster_id == cid)
            ).scalar_one()
            assert n_events == 1  # only the FIRST call wrote an evidence row
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.id == obs.id))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_apply_stage_transition_row_lock_prevents_lost_update():
    """The exact failure scenario the architecture review identified: two
    writers race to move the SAME cluster to two different stages. Without
    with_for_update(), a stale-read writer can commit last and silently
    regress the stage (e.g. active -> warming). With the lock, the second
    writer's evaluate_stage() call happens against post-first-writer state,
    so it can only move stage forward, never backward."""
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, EvidenceEvent
    from product.stage_engine import apply_stage_transition

    with SessionLocal() as s:
        cluster = CampaignCluster(cluster_key="test-race-stage-key", target_brand="zztest",
                                  stage="new", first_seen=dt.datetime.now(dt.timezone.utc),
                                  last_seen=dt.datetime.now(dt.timezone.utc))
        s.add(cluster)
        s.flush()
        cid = cluster.id
        obs_a = CtObservation(raw_host="zztest-race-a.tk", registered_domain="zztest-race-a.tk",
                              event_ts=dt.datetime.now(dt.timezone.utc), enrichment_level="tier1")
        s.add(obs_a)
        s.flush()
        s.add(ClusterMember(cluster_id=cid, observation_id=obs_a.id))
        s.commit()
    try:
        # Writer A (e.g. ingest_observations.py): sees tier1 enrichment -> "warming".
        # Writer B (e.g. the content probe): sees HTTP evidence -> "active".
        # Run them as two SEPARATE sessions (separate DB connections), simulating
        # two concurrent Airflow tasks. apply_stage_transition's row lock means
        # B, running after A commits (even if B's inputs were computed before),
        # must reflect at least A's floor -- the final stage must be the
        # stronger of the two ("active"), never a regression back to "warming".
        with SessionLocal() as session_a:
            result_a = apply_stage_transition(session_a, cid)
            assert result_a["new_stage"] == "warming"

        with SessionLocal() as session_b:
            result_b = apply_stage_transition(
                session_b, cid,
                evidence=[{"event_type": "content_probe_result", "detail": {"http_status": 200}}],
            )
            assert result_b["new_stage"] == "active"

        # Final state must be "active", not regressed by a stale write.
        with SessionLocal() as verify:
            final = verify.execute(
                select(CampaignCluster).where(CampaignCluster.id == cid)
            ).scalar_one()
            assert final.stage == "active"
    finally:
        with SessionLocal() as cleanup:
            cleanup.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            cleanup.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            cleanup.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            cleanup.execute(delete(CtObservation).where(CtObservation.raw_host == "zztest-race-a.tk"))
            cleanup.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_disposition_locks_and_survives_automatic_reevaluation():
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, EvidenceEvent
    from product.stage_engine import apply_stage_transition

    with SessionLocal() as s:
        cluster = CampaignCluster(cluster_key="test-lock-stage-key", target_brand="zztest",
                                  stage="new", first_seen=dt.datetime.now(dt.timezone.utc),
                                  last_seen=dt.datetime.now(dt.timezone.utc))
        s.add(cluster)
        s.flush()
        cid = cluster.id
        obs = CtObservation(raw_host="zztest-lock.tk", registered_domain="zztest-lock.tk",
                            event_ts=dt.datetime.now(dt.timezone.utc))
        s.add(obs)
        s.flush()
        s.add(ClusterMember(cluster_id=cid, observation_id=obs.id))
        s.commit()
    try:
        with SessionLocal() as s:
            r = apply_stage_transition(s, cid, disposition={"verdict": "suppressed"}, actor="analyst_zz")
            assert r["new_stage"] == "suppressed" and r["locked"] is True

        with SessionLocal() as s:
            cluster = s.execute(select(CampaignCluster).where(CampaignCluster.id == cid)).scalar_one()
            assert cluster.stage_locked_by == "analyst_zz"
            assert cluster.stage_locked_at is not None

        # Now an automatic call (e.g. ingest advancing enrichment) must NOT
        # unlock or change the analyst's suppressed verdict.
        with SessionLocal() as s:
            r2 = apply_stage_transition(s, cid)  # no disposition -- automatic path
            assert r2["locked"] is True
            assert r2["changed"] is False

        with SessionLocal() as s:
            cluster = s.execute(select(CampaignCluster).where(CampaignCluster.id == cid)).scalar_one()
            assert cluster.stage == "suppressed"  # still locked, unchanged
    finally:
        with SessionLocal() as cleanup:
            cleanup.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            cleanup.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            cleanup.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            cleanup.execute(delete(CtObservation).where(CtObservation.raw_host == "zztest-lock.tk"))
            cleanup.commit()
