"""Campaign assembly: pure clustering logic runs without a DB; the
merge-not-split identity behavior (W3) is verified against the live app-db and
skips cleanly when unreachable.
"""
import datetime as dt

import pytest

from product.assemble_campaigns import (
    _burst_proximity,
    _lexical_similarity,
    _overlap_fraction,
    cluster_key_for,
    compute_membership_score,
    lexical_family_root,
    target_brand_for,
)
from product.db import ping


# ---------- pure logic (no DB) ----------

def test_cluster_key_is_stable_and_distinct():
    a = cluster_key_for("paypal", "2026-07-03", "tk:h")
    assert a == cluster_key_for("paypal", "2026-07-03", "tk:h")   # deterministic
    assert a != cluster_key_for("paypal", "2026-07-04", "tk:h")   # day matters
    assert a != cluster_key_for("apple", "2026-07-03", "tk:h")    # brand matters
    assert a != cluster_key_for("paypal", "2026-07-03", "xyz:l")  # family matters


def test_lexical_family_root():
    assert lexical_family_root("paypal-a-b-c.tk") == "tk:h"   # >=3 hyphens
    assert lexical_family_root("paypal.xyz") == "xyz:l"
    assert lexical_family_root("secure-paypal.com") == "com:l"  # 1 hyphen


def test_target_brand_prefers_higher_priority():
    brands = [("paypal", ["paypal"], 200), ("apple", ["apple", "appleid"], 150)]
    assert target_brand_for("secure-paypal.tk", brands) == "paypal"
    assert target_brand_for("appleid-login.tk", brands) == "apple"
    assert target_brand_for("example.com", brands) is None
    # both present -> higher priority (iterated first) wins
    assert target_brand_for("paypal-apple.tk", brands) == "paypal"


def test_target_brand_excludes_brands_own_infra():
    # A brand's own legit infra must not be attributed as impersonation -- this
    # is the Day-1 provider-allowlist reused for attribution.
    brands = [("microsoft", ["microsoft"], 150)]
    self_domains = {"microsoft": ["microsoft.com", "microsoftonline.com"]}
    assert target_brand_for("graphql.fabric.microsoft.com", brands, self_domains) is None
    assert target_brand_for("microsoft365-pentesting.com", brands, self_domains) == "microsoft"
    # lookalike trick under a fake apex is still attributed
    assert target_brand_for("login.microsoft.com.evil.tk", brands, self_domains) == "microsoft"


# ---------- weighted membership scoring (Track B, no DB) ----------

def test_lexical_similarity_no_others_is_zero():
    assert _lexical_similarity("a.com", []) == 0.0


def test_lexical_similarity_identical_hosts_is_one():
    assert _lexical_similarity("paypal-login.tk", ["paypal-login.tk"]) == 1.0


def test_lexical_similarity_closer_host_scores_higher():
    close = _lexical_similarity("paypal-login-a.tk", ["paypal-login-b.tk"])
    far = _lexical_similarity("paypal-login-a.tk", ["totally-different-xyz.tk"])
    assert close > far


def test_overlap_fraction_empty_or_missing_is_zero():
    assert _overlap_fraction(None, ["AS123"]) == 0.0
    assert _overlap_fraction("AS123", []) == 0.0


def test_overlap_fraction_case_insensitive_partial_match():
    assert _overlap_fraction("AS123", ["as123", "AS999"]) == 0.5


def test_burst_proximity_neutral_with_nothing_to_compare():
    assert _burst_proximity(dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc), []) == 0.5


def test_burst_proximity_decays_with_distance():
    base = dt.datetime(2026, 7, 3, 12, 0, tzinfo=dt.timezone.utc)
    close = _burst_proximity(base + dt.timedelta(hours=1), [base])
    far = _burst_proximity(base + dt.timedelta(hours=23), [base])
    assert close > far
    assert close == pytest.approx(1.0 - 1 / 24, abs=1e-6)


def test_compute_membership_score_first_member_gets_baseline_score():
    from product.models import CtObservation
    o = CtObservation(raw_host="a.tk", event_ts=dt.datetime(2026, 7, 3, tzinfo=dt.timezone.utc))
    # brand(0.30 fixed) + burst(0.25*0.5 neutral) + lexical(0) + asn(0) + registrar(0)
    assert compute_membership_score(o, []) == pytest.approx(0.30 + 0.125, abs=1e-4)


def test_compute_membership_score_strong_overlap_scores_higher_than_none():
    from product.models import CtObservation
    ts = dt.datetime(2026, 7, 3, 12, 0, tzinfo=dt.timezone.utc)
    existing = [CtObservation(raw_host="paypal-login-a.tk", event_ts=ts,
                              sample_asn="AS111", registrar="NameCheap")]
    strong = CtObservation(raw_host="paypal-login-b.tk", event_ts=ts,
                           sample_asn="AS111", registrar="NameCheap")
    weak = CtObservation(raw_host="zzz-unrelated.xyz", event_ts=ts + dt.timedelta(hours=20),
                         sample_asn="AS999", registrar="GoDaddy")
    assert compute_membership_score(strong, existing) > compute_membership_score(weak, existing)


# ---------- live merge-not-split (W3) ----------

@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_burst_forms_one_cluster_and_second_batch_merges():
    from sqlalchemy import delete, select

    from product.assemble_campaigns import assemble
    from product.db import SessionLocal
    from product.models import (
        CampaignCluster,
        ClusterMember,
        CtObservation,
        WatchlistBrand,
    )

    BRAND = "zztestbrand"  # unique -> won't collide with real watchlist/data
    day = dt.datetime(2026, 7, 3, 9, 0, 0, tzinfo=dt.timezone.utc)

    def add_obs(s, host):
        s.add(CtObservation(raw_host=host, registered_domain=host,
                            event_ts=day, risk_score=0.9))

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=BRAND, priority=999, active=True))
            # first burst: two same-brand, same-day, same-family hosts
            add_obs(s, f"{BRAND}-login-a-b.tk")
            add_obs(s, f"{BRAND}-secure-c-d.tk")
            s.commit()

            assemble(min_risk=0.5)
            clusters = s.execute(
                select(CampaignCluster).where(CampaignCluster.target_brand == BRAND)
            ).scalars().all()
            assert len(clusters) == 1                      # one campaign
            assert clusters[0].observation_count == 2

            # second batch: another host, same brand/day/family -> MERGE
            add_obs(s, f"{BRAND}-verify-e-f.tk")
            s.commit()
            assemble(min_risk=0.5)
            s.expire_all()
            clusters = s.execute(
                select(CampaignCluster).where(CampaignCluster.target_brand == BRAND)
            ).scalars().all()
            assert len(clusters) == 1                      # still ONE (merged, not split)
            assert clusters[0].observation_count == 3
        finally:
            ids = s.execute(
                select(CampaignCluster.id).where(CampaignCluster.target_brand == BRAND)
            ).scalars().all()
            if ids:
                s.execute(delete(ClusterMember).where(ClusterMember.cluster_id.in_(ids)))
                s.execute(delete(CampaignCluster).where(CampaignCluster.id.in_(ids)))
            s.execute(delete(CtObservation).where(CtObservation.raw_host.like(f"{BRAND}-%")))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == BRAND))
            s.commit()


# ---------- live suppression integration (Track B) ----------

@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_suppressed_observation_never_forms_a_new_cluster():
    """An observation matching an active suppression rule must be excluded at
    candidate-selection time -- it should never form (or join) a cluster."""
    from sqlalchemy import delete, select

    from product.assemble_campaigns import assemble
    from product.db import SessionLocal
    from product.models import CampaignCluster, CtObservation, SuppressionRule, WatchlistBrand

    BRAND = "zzsupprbrand"
    day = dt.datetime(2026, 7, 4, 10, 0, 0, tzinfo=dt.timezone.utc)
    host = f"{BRAND}-login-a-b.tk"

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=BRAND, priority=999, active=True))
            s.add(SuppressionRule(rule_type="domain", match_value=host, created_by="test", active=True))
            s.add(CtObservation(raw_host=host, registered_domain=host, event_ts=day, risk_score=0.9))
            s.commit()

            result = assemble(min_risk=0.5)
            assert result["suppressed_candidates"] >= 1
            clusters = s.execute(
                select(CampaignCluster).where(CampaignCluster.target_brand == BRAND)
            ).scalars().all()
            assert clusters == []  # never formed -- excluded before grouping
        finally:
            s.execute(delete(CtObservation).where(CtObservation.raw_host == host))
            s.execute(delete(SuppressionRule).where(SuppressionRule.match_value == host))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == BRAND))
            s.commit()


@pytest.mark.skipif(not ping(), reason="app-db not reachable (docker compose up -d app-db)")
def test_existing_cluster_transitions_to_suppressed_when_rule_added_later():
    """A cluster formed BEFORE a suppression rule existed must still get
    pushed to stage=suppressed once all its members match a newly-added rule
    -- this is reevaluate_suppressed_clusters(), separate from candidate-time
    exclusion (which alone would never touch an already-formed cluster again)."""
    from sqlalchemy import delete, select

    from product.assemble_campaigns import assemble
    from product.db import SessionLocal
    from product.models import CampaignCluster, ClusterMember, CtObservation, SuppressionRule, WatchlistBrand

    BRAND = "zzsupprexisting"
    day = dt.datetime(2026, 7, 4, 11, 0, 0, tzinfo=dt.timezone.utc)
    host = f"{BRAND}-secure-a-b.tk"

    with SessionLocal() as s:
        try:
            s.add(WatchlistBrand(brand_name=BRAND, priority=999, active=True))
            s.add(CtObservation(raw_host=host, registered_domain=host, event_ts=day, risk_score=0.9))
            s.commit()

            assemble(min_risk=0.5)  # forms the cluster, no suppression rule yet
            cluster = s.execute(
                select(CampaignCluster).where(CampaignCluster.target_brand == BRAND)
            ).scalar_one()
            assert cluster.stage != "suppressed"

            # NOW add a suppression rule matching the (only) member, and re-run
            s.add(SuppressionRule(rule_type="domain", match_value=host, created_by="test", active=True))
            s.commit()
            assemble(min_risk=0.5)

            s.expire_all()
            cluster = s.execute(
                select(CampaignCluster).where(CampaignCluster.target_brand == BRAND)
            ).scalar_one()
            assert cluster.stage == "suppressed"
        finally:
            ids = s.execute(
                select(CampaignCluster.id).where(CampaignCluster.target_brand == BRAND)
            ).scalars().all()
            if ids:
                s.execute(delete(ClusterMember).where(ClusterMember.cluster_id.in_(ids)))
                s.execute(delete(CampaignCluster).where(CampaignCluster.id.in_(ids)))
            s.execute(delete(CtObservation).where(CtObservation.raw_host == host))
            s.execute(delete(SuppressionRule).where(SuppressionRule.match_value == host))
            s.execute(delete(WatchlistBrand).where(WatchlistBrand.brand_name == BRAND))
            s.commit()
