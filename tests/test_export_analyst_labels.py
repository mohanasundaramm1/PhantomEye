"""Disposition export: live test against the real app-db (synthetic data),
skips cleanly when unreachable."""
import datetime as dt

import pytest

from product.db import ping

pytestmark = pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")

TAG = "zzexport"


def test_export_uses_latest_verdict_and_maps_label_correctly():
    from sqlalchemy import delete, select

    from product.db import SessionLocal
    from product.export_analyst_labels import build_export
    from product.models import AnalystDisposition, CampaignCluster, ClusterMember, CtObservation, WatchlistBrand

    now = dt.datetime.now(dt.timezone.utc)
    host = f"{TAG}-login-a.tk"

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=TAG, priority=999, active=True))
            obs = CtObservation(raw_host=host, registered_domain=host, event_ts=now, risk_score=0.9)
            s.add(obs)
            s.flush()
            cluster = CampaignCluster(cluster_key=f"{TAG}-cluster", target_brand=TAG,
                                      stage="new", first_seen=now, last_seen=now)
            s.add(cluster)
            s.flush()
            s.add(ClusterMember(cluster_id=cluster.id, observation_id=obs.id))
            s.commit()
            cid = cluster.id

            # suppressed first, THEN confirmed -- export must reflect the LATEST verdict
            s.add(AnalystDisposition(cluster_id=cid, verdict="suppressed", analyst="t",
                                     created_at=now - dt.timedelta(hours=1)))
            s.add(AnalystDisposition(cluster_id=cid, verdict="confirmed", analyst="t", created_at=now))
            s.commit()

            df = build_export(s)
            row = df[df["raw_host"] == host]
            assert len(row) == 1
            assert row.iloc[0]["verdict"] == "confirmed"
            assert row.iloc[0]["label"] == 1
        finally:
            s.execute(delete(AnalystDisposition).where(AnalystDisposition.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.raw_host == host))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == TAG))
            s.commit()


def test_export_maps_suppressed_and_benign_to_negative_label():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.export_analyst_labels import build_export
    from product.models import AnalystDisposition, CampaignCluster, ClusterMember, CtObservation, WatchlistBrand

    now = dt.datetime.now(dt.timezone.utc)
    host = f"{TAG}-suppr-a.tk"

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=TAG, priority=999, active=True))
            obs = CtObservation(raw_host=host, registered_domain=host, event_ts=now, risk_score=0.9)
            s.add(obs)
            s.flush()
            cluster = CampaignCluster(cluster_key=f"{TAG}-cluster2", target_brand=TAG,
                                      stage="suppressed", first_seen=now, last_seen=now)
            s.add(cluster)
            s.flush()
            s.add(ClusterMember(cluster_id=cluster.id, observation_id=obs.id))
            s.commit()
            cid = cluster.id
            s.add(AnalystDisposition(cluster_id=cid, verdict="suppressed", analyst="t", created_at=now))
            s.commit()

            df = build_export(s)
            row = df[df["raw_host"] == host]
            assert len(row) == 1
            assert row.iloc[0]["label"] == 0
        finally:
            s.execute(delete(AnalystDisposition).where(AnalystDisposition.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.raw_host == host))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == TAG))
            s.commit()
