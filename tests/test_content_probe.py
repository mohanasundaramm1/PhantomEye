"""Content probe: disabled-by-default is the single most important behavior
here (real opsec consequence if it silently activates), so it gets its own
hard guard using a fetcher that FAILS the test if ever invoked. Enabled-mode
extraction logic is tested with injectable fetchers, matching tiers.py's
dns_fetch/whois_fetch pattern -- no real network calls anywhere in this file.
"""
from ct.enrich.circuit import CircuitBreaker
from ct.enrich.ratelimit import TokenBucket
from product.content_probe import (
    content_fingerprint,
    extract_title,
    has_password_form,
    probe_target,
    run_probe,
)


def _fail_if_called(*a, **k):
    raise AssertionError("network fetcher was invoked despite content_probe being disabled")


# ---------- the one behavior that matters most ----------

def test_disabled_by_default_makes_zero_network_calls():
    cfg = {"enabled": False}
    result = run_probe(cfg=cfg, http_fetch=_fail_if_called, mx_fetch=_fail_if_called)
    assert result == {"ok": True, "enabled": False, "probed": 0}


def test_disabled_is_the_config_file_default():
    from product.content_probe import load_probe_config
    assert load_probe_config()["enabled"] is False


# ---------- extraction (pure) ----------

def test_extract_title_basic():
    assert extract_title("<html><head><title>Secure Login</title></head></html>") == "Secure Login"


def test_extract_title_collapses_whitespace_and_none_when_absent():
    assert extract_title("<title>\n  Multi\n  Line  </title>") == "Multi Line"
    assert extract_title("<html><body>no title tag</body></html>") is None
    assert extract_title("") is None


def test_has_password_form_detects_field_case_insensitive():
    assert has_password_form('<input TYPE="Password" name="pw">') is True
    assert has_password_form("<input type='text'>") is False
    assert has_password_form("") is False


def test_content_fingerprint_stable_and_distinct():
    a = content_fingerprint(200, "Login", True)
    assert a == content_fingerprint(200, "Login", True)  # deterministic
    assert a != content_fingerprint(200, "Login", False)  # form presence matters
    assert a != content_fingerprint(404, "Login", True)   # status matters


# ---------- probe_target with injectable fetchers ----------

def _cfg():
    return {"timeout_seconds": 8, "user_agent": "test-ua/0.1"}


def test_probe_target_extracts_full_result_on_success():
    def fake_http(url, timeout, ua):
        assert url.startswith("https://")  # tries https first
        return {"status_code": 200, "final_url": url,
                "text": '<title>Fake Bank Login</title><input type="password">'}

    def fake_mx(domain):
        return True

    result = probe_target("evil.tk", _cfg(), CircuitBreaker("test"), TokenBucket(100), fake_http, fake_mx)
    assert result["http_status"] == 200
    assert result["title"] == "Fake Bank Login"
    assert result["has_password_form"] is True
    assert result["mx_present"] is True
    assert "error" not in result


def test_probe_target_falls_back_to_http_when_https_fails():
    from ct.enrich.tiers import EnrichFailure

    calls = []

    def fake_http(url, timeout, ua):
        calls.append(url)
        if url.startswith("https://"):
            raise EnrichFailure("content_probe", "connection refused")
        return {"status_code": 200, "final_url": url, "text": "<title>OK</title>"}

    result = probe_target("plain.tk", _cfg(), CircuitBreaker("test"), TokenBucket(100), fake_http, lambda d: False)
    assert calls == ["https://plain.tk/", "http://plain.tk/"]
    assert result["http_status"] == 200


def test_probe_target_returns_error_dict_when_both_schemes_fail():
    from ct.enrich.tiers import EnrichFailure

    def always_fails(url, timeout, ua):
        raise EnrichFailure("content_probe", "timeout>8s")

    result = probe_target("dead.tk", _cfg(), CircuitBreaker("test"), TokenBucket(100), always_fails, lambda d: False)
    assert "error" in result
    assert "http_status" not in result


def test_probe_target_respects_open_circuit():
    breaker = CircuitBreaker("test", failure_threshold=1)
    breaker.record_failure()  # opens the circuit
    result = probe_target("x.tk", _cfg(), breaker, TokenBucket(100), _fail_if_called, _fail_if_called)
    assert result == {"error": "circuit open"}


def test_probe_target_mx_failure_does_not_invalidate_http_result():
    from ct.enrich.tiers import EnrichFailure

    def fake_http(url, timeout, ua):
        return {"status_code": 200, "final_url": url, "text": "<title>Fine</title>"}

    def failing_mx(domain):
        raise EnrichFailure("content_probe", "dns error")

    result = probe_target("x.tk", _cfg(), CircuitBreaker("test"), TokenBucket(100), fake_http, failing_mx)
    assert result["http_status"] == 200
    assert result["mx_present"] is False
    assert "error" not in result


# ---------- live full round-trip (enabled mode, injected fetchers -- no real network) ----------

def test_run_probe_enabled_writes_evidence_and_advances_stage():
    """Full round-trip against the real app-db: enabled=true + injected
    fetchers (still zero real network calls) -- probes a real cluster's
    member, writes http_status/content_fingerprint/mx_present to
    ct_observations, an evidence_events row, and calls apply_stage_transition
    (call site 4/4), which should push a "new"-stage cluster to "active"."""
    import datetime as dt

    import pytest as _pytest
    from sqlalchemy import delete, select

    from product.db import SessionLocal, ping
    if not ping():
        _pytest.skip("app-db not reachable (docker compose up -d app-db)")

    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent, WatchlistBrand

    BRAND = "zzprobebrand"
    host = f"{BRAND}-login-a-b.tk"
    day = dt.datetime(2026, 7, 5, 8, 0, 0, tzinfo=dt.timezone.utc)

    def fake_http(url, timeout, ua):
        return {"status_code": 200, "final_url": url,
                "text": '<title>Fake Login</title><input type="password">'}

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=BRAND, priority=999, active=True))
            obs = CtObservation(raw_host=host, registered_domain=host, event_ts=day, risk_score=0.9)
            s.add(obs)
            s.flush()
            cluster = CampaignCluster(cluster_key="zz-probe-cluster", target_brand=BRAND,
                                      stage="new", confidence_score=0.9,
                                      first_seen=day, last_seen=day, observation_count=1)
            s.add(cluster)
            s.flush()
            s.add(ClusterMember(cluster_id=cluster.id, observation_id=obs.id, membership_score=0.9))
            s.commit()
            cid, oid = cluster.id, obs.id

            result = run_probe(
                cfg={"enabled": True, "max_targets_per_cluster": 2,
                     "rate_limit_rps": 100, "timeout_seconds": 8},
                # cluster_ids scopes this to EXACTLY the synthetic cluster above --
                # a confidence-only filter here previously matched real production
                # clusters too and corrupted them with this test's fake fetcher
                # output (see run_probe()'s docstring for the full incident).
                cluster_ids=[cid],
                http_fetch=fake_http, mx_fetch=lambda d: True,
            )
            assert result["enabled"] is True
            assert result["probed"] >= 1

            s.expire_all()
            refreshed_obs = s.get(CtObservation, oid)
            assert refreshed_obs.http_status == 200
            assert refreshed_obs.mx_present is True
            assert refreshed_obs.content_fingerprint is not None

            evidence = s.execute(
                select(EvidenceEvent).where(EvidenceEvent.cluster_id == cid,
                                            EvidenceEvent.event_type == "content_probe_result")
            ).scalars().all()
            assert len(evidence) >= 1

            refreshed_cluster = s.get(CampaignCluster, cid)
            assert refreshed_cluster.stage == "active"  # live HTTP evidence advanced it
        finally:
            s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
            s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
            s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.raw_host == host))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == BRAND))
            s.commit()


def test_cluster_ids_isolates_run_probe_from_other_high_confidence_clusters():
    """The exact regression this incident calls for: a DECOY cluster with
    confidence_score high enough that a naive min_confidence-only filter
    would have swept it in (simulating a real production cluster sitting
    alongside a test's synthetic one) must be completely untouched when
    cluster_ids scopes the run elsewhere -- no probe call, no evidence row,
    no stage change."""
    import datetime as dt

    import pytest as _pytest
    from sqlalchemy import delete, select

    from product.db import SessionLocal, ping
    if not ping():
        _pytest.skip("app-db not reachable (docker compose up -d app-db)")

    from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent, WatchlistBrand

    BRAND = "zzisolationbrand"
    day = dt.datetime(2026, 7, 5, 9, 0, 0, tzinfo=dt.timezone.utc)
    target_host = f"{BRAND}-target.tk"
    decoy_host = f"{BRAND}-decoy.tk"

    calls = []

    def tracking_http(url, timeout, ua):
        calls.append(url)
        return {"status_code": 200, "final_url": url, "text": "<title>OK</title>"}

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=BRAND, priority=999, active=True))

            target_obs = CtObservation(raw_host=target_host, registered_domain=target_host,
                                       event_ts=day, risk_score=0.9)
            decoy_obs = CtObservation(raw_host=decoy_host, registered_domain=decoy_host,
                                      event_ts=day, risk_score=0.9)
            s.add_all([target_obs, decoy_obs])
            s.flush()

            target_cluster = CampaignCluster(cluster_key=f"{BRAND}-target-key", target_brand=BRAND,
                                             stage="new", confidence_score=0.9,
                                             first_seen=day, last_seen=day, observation_count=1)
            # decoy has HIGHER confidence than target -- if isolation were broken,
            # it would be the first one swept in by a confidence-only filter
            decoy_cluster = CampaignCluster(cluster_key=f"{BRAND}-decoy-key", target_brand=BRAND,
                                            stage="new", confidence_score=0.99,
                                            first_seen=day, last_seen=day, observation_count=1)
            s.add_all([target_cluster, decoy_cluster])
            s.flush()
            s.add(ClusterMember(cluster_id=target_cluster.id, observation_id=target_obs.id))
            s.add(ClusterMember(cluster_id=decoy_cluster.id, observation_id=decoy_obs.id))
            s.commit()
            target_cid, decoy_cid = target_cluster.id, decoy_cluster.id

            run_probe(
                cfg={"enabled": True, "max_targets_per_cluster": 2, "rate_limit_rps": 100, "timeout_seconds": 8},
                cluster_ids=[target_cid],  # decoy deliberately NOT included
                http_fetch=tracking_http, mx_fetch=lambda d: True,
            )

            assert calls == [f"https://{target_host}/"]  # decoy never fetched

            s.expire_all()
            decoy_after = s.get(CampaignCluster, decoy_cid)
            decoy_obs_after = s.get(CtObservation, decoy_obs.id)
            assert decoy_after.stage == "new"                      # untouched
            assert decoy_obs_after.http_status is None              # untouched
            decoy_evidence = s.execute(
                select(EvidenceEvent).where(EvidenceEvent.cluster_id == decoy_cid)
            ).scalars().all()
            assert decoy_evidence == []                             # no evidence written
        finally:
            for cid in (target_cid, decoy_cid):
                s.execute(delete(EvidenceEvent).where(EvidenceEvent.cluster_id == cid))
                s.execute(delete(ClusterMember).where(ClusterMember.cluster_id == cid))
                s.execute(delete(CampaignCluster).where(CampaignCluster.id == cid))
            s.execute(delete(CtObservation).where(CtObservation.raw_host.in_([target_host, decoy_host])))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == BRAND))
            s.commit()
