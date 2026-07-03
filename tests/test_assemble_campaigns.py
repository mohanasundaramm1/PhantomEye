"""Campaign assembly: pure clustering logic runs without a DB; the
merge-not-split identity behavior (W3) is verified against the live app-db and
skips cleanly when unreachable.
"""
import datetime as dt

import pytest

from product.assemble_campaigns import (
    cluster_key_for,
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
