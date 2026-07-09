"""Phase 6 egress export: product/export.py's pure formatting functions
(no DB needed -- they take already-fetched ORM instances) plus the
GET /campaigns/{id}/export endpoint (DB-backed, skips cleanly when app-db
isn't reachable, same pattern as tests/test_analyst_workflow_endpoints.py).
"""
import datetime as dt

import pytest

from product.db import ping
from product.export import campaign_to_json, campaign_to_stix
from product.models import AnalystDisposition, CampaignCluster, CtObservation

_DB = ping()


def _cluster(**kw):
    now = dt.datetime.now(dt.timezone.utc)
    defaults = dict(
        id=1, cluster_key="test-cluster-key", target_brand="apple", target_workflow="generic",
        stage="confirmed", confidence_score=0.87, summary_reason="test summary",
        first_seen=now, last_seen=now,
    )
    defaults.update(kw)
    return CampaignCluster(**defaults)


def _observation(**kw):
    now = dt.datetime.now(dt.timezone.utc)
    defaults = dict(
        id=1, raw_host="secure-apple-id.tk", registered_domain="secure-apple-id.tk",
        risk_score=0.91, registrar="Example Registrar", sample_asn="AS1234", event_ts=now,
    )
    defaults.update(kw)
    return CtObservation(**defaults)


def _disposition(**kw):
    now = dt.datetime.now(dt.timezone.utc)
    defaults = dict(
        id=1, cluster_id=1, verdict="confirmed", analyst="mohan",
        severity="high", notes="clear phishing kit", created_at=now,
    )
    defaults.update(kw)
    return AnalystDisposition(**defaults)


def test_campaign_to_json_shape_and_content():
    cluster = _cluster()
    obs = _observation()
    disposition = _disposition()

    result = campaign_to_json(cluster, [obs], disposition)

    assert result["export_format"] == "json"
    assert result["campaign"]["campaign_id"] == 1
    assert result["campaign"]["target_brand"] == "apple"
    assert result["disposition"]["verdict"] == "confirmed"
    assert result["disposition"]["analyst"] == "mohan"
    assert len(result["indicators"]) == 1
    assert result["indicators"][0]["domain"] == "secure-apple-id.tk"
    assert result["indicators"][0]["risk_score"] == 0.91


def test_campaign_to_json_no_disposition_is_null():
    result = campaign_to_json(_cluster(), [_observation()], None)
    assert result["disposition"] is None


def test_campaign_to_stix_produces_valid_bundle_shape():
    cluster = _cluster()
    obs = _observation()
    disposition = _disposition()

    bundle = campaign_to_stix(cluster, [obs], disposition)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")

    by_type = {}
    for o in bundle["objects"]:
        by_type.setdefault(o["type"], []).append(o)

    assert len(by_type["campaign"]) == 1
    campaign_obj = by_type["campaign"][0]
    assert campaign_obj["id"].startswith("campaign--")
    assert campaign_obj["spec_version"] == "2.1"
    assert "apple" in campaign_obj["name"]

    assert len(by_type["indicator"]) == 1
    indicator_obj = by_type["indicator"][0]
    assert indicator_obj["id"].startswith("indicator--")
    assert indicator_obj["pattern"] == "[domain-name:value = 'secure-apple-id.tk']"
    assert indicator_obj["pattern_type"] == "stix"

    assert len(by_type["relationship"]) == 1
    rel = by_type["relationship"][0]
    assert rel["source_ref"] == indicator_obj["id"]
    assert rel["target_ref"] == campaign_obj["id"]
    assert rel["relationship_type"] == "indicates"

    assert len(by_type["note"]) == 1
    assert "confirmed by mohan" in by_type["note"][0]["content"]

    # Every STIX timestamp uses the canonical millisecond+Z form, no matter
    # which model field it was sourced from (created_at has tz offset+micros,
    # event_ts is tz-aware -- both must normalize to the same shape).
    import re
    ts_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
    for o in bundle["objects"]:
        for field in ("created", "modified", "valid_from"):
            if field in o:
                assert ts_re.match(o[field]), f"{o['type']}.{field} = {o[field]!r} is not canonical STIX timestamp form"


def test_campaign_to_stix_falls_back_to_raw_host_when_registered_domain_missing():
    obs = _observation(registered_domain=None, raw_host="fallback-host.example.com")
    bundle = campaign_to_stix(_cluster(), [obs], None)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    assert "fallback-host.example.com" in indicators[0]["pattern"]
    assert bundle["x_phantomeye_skipped_domains"] == 0


def test_campaign_to_stix_no_disposition_omits_note():
    bundle = campaign_to_stix(_cluster(), [_observation()], None)
    assert not any(o["type"] == "note" for o in bundle["objects"])


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_export_endpoint_missing_campaign_is_404():
    from fastapi import HTTPException

    from api.main import export_campaign

    with pytest.raises(HTTPException) as ei:
        export_campaign(999999, format="json")
    assert ei.value.status_code == 404


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_export_endpoint_bad_format_is_422():
    from fastapi import HTTPException

    from api.main import export_campaign

    with pytest.raises(HTTPException) as ei:
        export_campaign(1, format="xml")
    assert ei.value.status_code == 422


@pytest.mark.skipif(not _DB, reason="app-db not reachable")
def test_export_endpoint_json_and_stix_against_live_fixture():
    from sqlalchemy import delete

    from product.db import SessionLocal

    from api.main import export_campaign

    now = dt.datetime.now(dt.timezone.utc)
    with SessionLocal() as s:
        cluster = CampaignCluster(
            cluster_key="zztest-export-cluster", target_brand="zztestexport",
            confidence_score=0.9, observation_count=1, stage="confirmed",
            summary_reason="zztest export fixture", first_seen=now, last_seen=now,
        )
        s.add(cluster)
        s.flush()

        obs = CtObservation(
            raw_host="zztest-export-domain.example.com",
            registered_domain="zztest-export-domain.example.com",
            risk_score=0.95, event_ts=now,
        )
        s.add(obs)
        s.flush()

        from product.models import ClusterMember
        member = ClusterMember(cluster_id=cluster.id, observation_id=obs.id, membership_reason="zztest")
        s.add(member)
        s.commit()
        cid, oid, mid = cluster.id, obs.id, member.id

        try:
            json_result = export_campaign(cid, format="json")
            assert json_result["campaign"]["campaign_id"] == cid
            assert len(json_result["indicators"]) == 1
            assert json_result["indicators"][0]["domain"] == "zztest-export-domain.example.com"

            stix_result = export_campaign(cid, format="stix")
            assert stix_result["type"] == "bundle"
            indicator_patterns = [o["pattern"] for o in stix_result["objects"] if o["type"] == "indicator"]
            assert "[domain-name:value = 'zztest-export-domain.example.com']" in indicator_patterns
        finally:
            s.execute(delete(ClusterMember).where(ClusterMember.id == mid))
            s.execute(delete(CtObservation).where(CtObservation.id == oid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.commit()
