"""product/repair_brand_matcher_clusters.py: assess_corruption() is read-only
and pure-ish (needs a session to read, never writes); repair()'s actual
delete/prune/EvidenceEvent behavior needs the live app-db (skips cleanly
when unreachable), same pattern as tests/test_stage_engine.py.
"""
import datetime as dt

import pytest

from product.db import ping


def _cluster(cluster_key, target_brand, stage_locked_by=None):
    from product.models import CampaignCluster
    now = dt.datetime.now(dt.timezone.utc)
    return CampaignCluster(cluster_key=cluster_key, target_brand=target_brand, stage="warming",
                           first_seen=now, last_seen=now, stage_locked_by=stage_locked_by)


def _obs(raw_host, risk_score=0.9):
    from product.models import CtObservation
    return CtObservation(raw_host=raw_host, registered_domain=raw_host,
                         event_ts=dt.datetime.now(dt.timezone.utc), enrichment_level="tier1",
                         risk_score=risk_score)


# Explicit brands=, not assess_corruption()'s default load_brands(session)
# query against the live watchlist_brands table: on a freshly-migrated DB
# with nothing seeded (exactly what CI runs against) there's no "apple" row,
# so every observation -- including the ones meant to be genuine matches --
# would come back unmatched, and assertions checking the "good" bucket would
# fail not because of a real bug but because the fixture never seeded its
# own brand data. Found live: 2 of these tests failed on a fresh CI-style
# DB while passing against a dev DB that happened to already have brands
# seeded from earlier manual `make seed-brands` runs.
_TEST_BRANDS = [("apple", ["apple"], 100)]


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_assess_corruption_identifies_fully_bogus_and_partial_clusters():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent
    from product.repair_brand_matcher_clusters import assess_corruption

    with SessionLocal() as s:
        bogus = _cluster("zztest-repair-fully-bogus", "apple")
        partial = _cluster("zztest-repair-partial", "apple")
        clean = _cluster("zztest-repair-clean", "apple")
        s.add_all([bogus, partial, clean])
        s.flush()

        bad_obs_1 = _obs("zztest-applesandbears.com")       # coincidental collision, no real match
        good_obs_1 = _obs("secure-apple-login-zztest.com")  # genuine match
        good_obs_2 = _obs("secure-apple-zztest2.com")
        s.add_all([bad_obs_1, good_obs_1, good_obs_2])
        s.flush()

        s.add_all([
            ClusterMember(cluster_id=bogus.id, observation_id=bad_obs_1.id),
            ClusterMember(cluster_id=partial.id, observation_id=bad_obs_1.id),
            ClusterMember(cluster_id=partial.id, observation_id=good_obs_1.id),
            ClusterMember(cluster_id=clean.id, observation_id=good_obs_2.id),
        ])
        s.commit()

        cluster_ids = [bogus.id, partial.id, clean.id]
        obs_ids = [bad_obs_1.id, good_obs_1.id, good_obs_2.id]
        try:
            # scoped to just this test's fixtures -- see assess_corruption()'s
            # docstring for why an unscoped call is dangerous against a
            # shared, non-isolated dev database.
            assessment = assess_corruption(s, brands=_TEST_BRANDS, cluster_ids=cluster_ids)
            assert bogus.id in assessment
            assert assessment[bogus.id]["good_observation_ids"] == []
            assert assessment[bogus.id]["bad_observation_ids"] == [bad_obs_1.id]

            assert partial.id in assessment
            assert set(assessment[partial.id]["good_observation_ids"]) == {good_obs_1.id}
            assert set(assessment[partial.id]["bad_observation_ids"]) == {bad_obs_1.id}

            # a cluster with zero bad members must not appear at all
            assert clean.id not in assessment
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id.in_(cluster_ids)))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id.in_(cluster_ids)))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id.in_(cluster_ids)))
            s.execute(delete(CtObservation).where(CtObservation.id.in_(obs_ids)))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_repair_dry_run_makes_no_changes(tmp_path):
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent
    from product.repair_brand_matcher_clusters import assess_corruption, repair

    with SessionLocal() as s:
        cluster = _cluster("zztest-repair-dryrun", "apple")
        s.add(cluster)
        s.flush()
        bad_obs = _obs("zztest-dryrun-applesandbears.com")
        s.add(bad_obs)
        s.flush()
        s.add(ClusterMember(cluster_id=cluster.id, observation_id=bad_obs.id))
        s.commit()
        cid, oid = cluster.id, bad_obs.id

        try:
            assessment = assess_corruption(s, brands=_TEST_BRANDS, cluster_ids=[cid])
            assert cid in assessment
            summary = repair(s, assessment, actor="test", dry_run=True,
                             deletion_log_path=str(tmp_path / "deletions.jsonl"))
            assert summary["dry_run"] is True
            assert any(d["cluster_id"] == cid for d in summary["deleted"])

            # nothing actually removed
            assert s.get(CampaignCluster, cid) is not None
            assert not (tmp_path / "deletions.jsonl").exists()
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.id == oid))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_repair_deletes_fully_bogus_cluster_and_logs_to_file(tmp_path):
    import json

    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent
    from product.repair_brand_matcher_clusters import assess_corruption, repair

    with SessionLocal() as s:
        cluster = _cluster("zztest-repair-apply-delete", "apple")
        s.add(cluster)
        s.flush()
        bad_obs = _obs("zztest-apply-applesandbears.com")
        s.add(bad_obs)
        s.flush()
        s.add(ClusterMember(cluster_id=cluster.id, observation_id=bad_obs.id))
        s.commit()
        cid, oid = cluster.id, bad_obs.id
        log_path = str(tmp_path / "deletions.jsonl")

        try:
            assessment = assess_corruption(s, brands=_TEST_BRANDS, cluster_ids=[cid])
            summary = repair(s, assessment, actor="test-actor", dry_run=False, deletion_log_path=log_path)
            assert any(d["cluster_id"] == cid for d in summary["deleted"])

            # cluster and its member are actually gone (cascade)
            assert s.get(CampaignCluster, cid) is None
            remaining_members = s.execute(
                select(ClusterMember).where(ClusterMember.cluster_id == cid)
            ).scalars().all()
            assert remaining_members == []

            # the deletion survives in the log file, not in a cascaded-away EvidenceEvent
            with open(log_path) as f:
                lines = [json.loads(l) for l in f]
            matching = [l for l in lines if l["cluster_id"] == cid]
            assert len(matching) == 1
            assert matching[0]["actor"] == "test-actor"
            assert matching[0]["target_brand"] == "apple"
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.id == oid))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_repair_prunes_partial_cluster_and_recomputes_confidence(tmp_path):
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent
    from product.repair_brand_matcher_clusters import assess_corruption, repair

    with SessionLocal() as s:
        cluster = _cluster("zztest-repair-apply-prune", "apple")
        s.add(cluster)
        s.flush()
        bad_obs = _obs("zztest-prune-applesandbears.com", risk_score=0.99)
        good_obs = _obs("secure-apple-login-zztest-prune.com", risk_score=0.8)
        s.add_all([bad_obs, good_obs])
        s.flush()
        s.add_all([
            ClusterMember(cluster_id=cluster.id, observation_id=bad_obs.id),
            ClusterMember(cluster_id=cluster.id, observation_id=good_obs.id),
        ])
        s.commit()
        cid, bad_id, good_id = cluster.id, bad_obs.id, good_obs.id

        try:
            assessment = assess_corruption(s, brands=_TEST_BRANDS, cluster_ids=[cid])
            assert set(assessment[cid]["good_observation_ids"]) == {good_id}
            repair(s, assessment, actor="test", dry_run=False,
                  deletion_log_path=str(tmp_path / "deletions.jsonl"))

            # cluster survives, only the bad member is gone
            refreshed = s.get(CampaignCluster, cid)
            assert refreshed is not None
            remaining = s.execute(
                select(ClusterMember.observation_id).where(ClusterMember.cluster_id == cid)
            ).scalars().all()
            assert set(remaining) == {good_id}

            # confidence recomputed off the surviving member's risk_score (0.8), not the pruned one's (0.99)
            assert refreshed.confidence_score < 0.9
            assert refreshed.observation_count == 1

            events = s.execute(
                select(EvidenceEvent).where(EvidenceEvent.cluster_id == cid,
                                            EvidenceEvent.event_type == "data_correction")
            ).scalars().all()
            assert len(events) == 1
            assert events[0].detail["pruned_count"] == 1
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.id.in_([bad_id, good_id])))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_repair_never_touches_locked_clusters(tmp_path):
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent
    from product.repair_brand_matcher_clusters import assess_corruption, repair

    with SessionLocal() as s:
        cluster = _cluster("zztest-repair-locked", "apple", stage_locked_by="some-analyst")
        s.add(cluster)
        s.flush()
        bad_obs = _obs("zztest-locked-applesandbears.com")
        s.add(bad_obs)
        s.flush()
        s.add(ClusterMember(cluster_id=cluster.id, observation_id=bad_obs.id))
        s.commit()
        cid, oid = cluster.id, bad_obs.id

        try:
            assessment = assess_corruption(s, brands=_TEST_BRANDS, cluster_ids=[cid])
            assert cid in assessment  # still flagged as bogus by the assessment itself
            summary = repair(s, assessment, actor="test", dry_run=False,
                             deletion_log_path=str(tmp_path / "deletions.jsonl"))

            assert any(x["cluster_id"] == cid for x in summary["skipped_locked"])
            assert not any(d["cluster_id"] == cid for d in summary["deleted"])
            # cluster and member both untouched
            assert s.get(CampaignCluster, cid) is not None
            remaining = s.execute(
                select(ClusterMember).where(ClusterMember.cluster_id == cid)
            ).scalars().all()
            assert len(remaining) == 1
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.id == oid))
            s.commit()
