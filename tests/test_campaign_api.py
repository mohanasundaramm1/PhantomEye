"""Campaign API endpoints. /health/pipeline is pure (always runs); the DB-backed
campaign endpoints skip cleanly when app-db isn't reachable. Calls the endpoint
functions directly to avoid a TestClient/httpx dependency."""
import pytest

from product.db import ping

_DB = ping()


def test_health_pipeline_shape():
    from api.main import health_pipeline

    j = health_pipeline()
    assert {"healthy", "app_db", "ct_raw", "scoring", "model", "ingest_watchdog"} <= set(j)
    assert isinstance(j["app_db"]["reachable"], bool)


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_campaigns_list_and_brand_filter():
    from api.main import list_campaigns

    j = list_campaigns(limit=5)
    assert j["available"] is True
    assert isinstance(j["campaigns"], list)
    # cards carry the queue-card contract fields
    if j["campaigns"]:
        card = j["campaigns"][0]
        assert {"campaign_id", "target_brand", "confidence_score", "member_count",
                "summary_reason"} <= set(card)
    # brand filter returns only that brand
    jm = list_campaigns(target_brand="microsoft")
    assert all(c["target_brand"] == "microsoft" for c in jm["campaigns"])


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_campaign_detail_missing_is_404():
    from fastapi import HTTPException

    from api.main import get_campaign

    with pytest.raises(HTTPException) as ei:
        get_campaign(999999)
    assert ei.value.status_code == 404
