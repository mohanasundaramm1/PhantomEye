"""Phase 4 analyst-workflow API additions: GET /analysts, the assignee
filter on GET /campaigns, and GET /campaigns/{id}/disposition-provenance.
DB-backed, skips cleanly when app-db isn't reachable -- same pattern as
tests/test_campaign_api.py. Calls endpoint functions directly to avoid a
TestClient/httpx dependency.
"""
import datetime as dt

import pytest

from product.db import ping

_DB = ping()


def _cluster(cluster_key, **kw):
    from product.models import CampaignCluster
    now = dt.datetime.now(dt.timezone.utc)
    defaults = dict(target_brand="apple", stage="warming", first_seen=now, last_seen=now)
    defaults.update(kw)
    return CampaignCluster(cluster_key=cluster_key, **defaults)


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_list_analysts_shape_and_active_filter():
    from product.db import SessionLocal
    from product.models import Analyst

    from api.main import list_analysts

    with SessionLocal() as s:
        active = Analyst(username="zztest-active-analyst", display_name="ZZ Active", active=True)
        inactive = Analyst(username="zztest-inactive-analyst", display_name="ZZ Inactive", active=False)
        s.add_all([active, inactive])
        s.commit()
        ids = [active.id, inactive.id]

        try:
            j = list_analysts(active_only=True)
            assert j["available"] is True
            usernames = {a["username"] for a in j["analysts"]}
            assert "zztest-active-analyst" in usernames
            assert "zztest-inactive-analyst" not in usernames

            j_all = list_analysts(active_only=False)
            usernames_all = {a["username"] for a in j_all["analysts"]}
            assert "zztest-inactive-analyst" in usernames_all
        finally:
            from sqlalchemy import delete
            s.execute(delete(Analyst).where(Analyst.id.in_(ids)))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_campaigns_assignee_filter_returns_only_that_assignee():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import CampaignCluster

    from api.main import list_campaigns

    with SessionLocal() as s:
        mine = _cluster("zztest-assignee-mine", confidence_score=0.9, assignee="zztest-analyst-a")
        theirs = _cluster("zztest-assignee-theirs", confidence_score=0.9, assignee="zztest-analyst-b")
        s.add_all([mine, theirs])
        s.commit()
        ids = [mine.id, theirs.id]

        try:
            j = list_campaigns(assignee="zztest-analyst-a", min_confidence=0.0)
            campaign_ids = {c["campaign_id"] for c in j["campaigns"]}
            assert mine.id in campaign_ids
            assert theirs.id not in campaign_ids
        finally:
            s.execute(delete(CampaignCluster).where(CampaignCluster.id.in_(ids)))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_disposition_provenance_missing_campaign_is_404():
    from fastapi import HTTPException

    from api.main import disposition_provenance

    with pytest.raises(HTTPException) as ei:
        disposition_provenance(999999)
    assert ei.value.status_code == 404


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_disposition_provenance_no_disposition_recorded():
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import CampaignCluster

    from api.main import disposition_provenance

    with SessionLocal() as s:
        cluster = _cluster("zztest-provenance-no-disposition")
        s.add(cluster)
        s.commit()
        cid = cluster.id

        try:
            j = disposition_provenance(cid)
            assert j["available"] is True
            assert j["has_disposition"] is False
        finally:
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.commit()


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_disposition_provenance_future_disposition_has_no_eligible_run_yet():
    # A disposition dated far in the future is guaranteed to have no
    # training run after it -- deterministic without depending on the
    # real, non-injectable ml/models/registry/ contents matching any
    # specific fixture.
    from sqlalchemy import delete

    from product.db import SessionLocal
    from product.models import AnalystDisposition, CampaignCluster

    from api.main import disposition_provenance

    with SessionLocal() as s:
        cluster = _cluster("zztest-provenance-future")
        s.add(cluster)
        s.flush()
        far_future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650)
        disposition = AnalystDisposition(cluster_id=cluster.id, verdict="confirmed", analyst="zztest",
                                         created_at=far_future)
        s.add(disposition)
        s.commit()
        cid = cluster.id

        try:
            j = disposition_provenance(cid)
            assert j["available"] is True
            assert j["has_disposition"] is True
            assert j["disposition"]["verdict"] == "confirmed"
            assert j["eligible_training_run"] is None
        finally:
            s.execute(delete(AnalystDisposition).where(AnalystDisposition.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.commit()
