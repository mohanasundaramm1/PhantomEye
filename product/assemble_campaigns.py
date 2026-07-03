# product/assemble_campaigns.py
"""Assemble candidate observations into brand-attributed campaign clusters.

One deterministic rule for the vertical slice: group candidate observations that
share a target brand AND fall in the same certificate-issuance burst window
(calendar day of event_ts), refined by a coarse lexical family.

Cluster identity (W3 decision):
    cluster_key = sha1(target_brand | burst_day | lexical_family_root)
    - A run finds the existing cluster by key and MERGES new observations into
      it (grows first_seen/last_seen/count); clusters are never auto-split.
    - Membership is idempotent (unique cluster_id+observation_id, ON CONFLICT DO
      NOTHING), so re-running is safe and only adds genuinely new members.

Deferred to later tracks (documented, not silently missing):
    - richer clustering signals (lexical family, ASN/registrar/nameserver
      overlap, SAN patterns) with a weighted membership score -> Track B
    - stage transitions + evidence timeline -> Track B/C

Run:
    python -m product.assemble_campaigns [--min-risk 0.5]
"""
from __future__ import annotations

import argparse
import hashlib
import os
from datetime import timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from product.db import SessionLocal
from product.models import (
    CampaignCluster,
    ClusterMember,
    CtObservation,
    WatchlistBrand,
)


def load_brands(session) -> list[tuple[str, list[str], int]]:
    """Active watchlist brands as (brand_name, [match_tokens], priority),
    highest priority first. match_tokens = brand_name + aliases."""
    rows = session.execute(
        select(WatchlistBrand).where(WatchlistBrand.active.is_(True))
    ).scalars().all()
    brands = []
    for b in rows:
        tokens = [b.brand_name.lower()]
        if b.aliases:
            tokens += [a.strip().lower() for a in b.aliases.split(",") if a.strip()]
        brands.append((b.brand_name.lower(), tokens, int(b.priority)))
    brands.sort(key=lambda x: -x[2])
    return brands


def target_brand_for(host: str, brands) -> str | None:
    """Attribute a host to the highest-priority watchlist brand whose name/alias
    appears in it. Substring match for the slice; token-boundary matching is a
    Track B refinement (so e.g. 'pineapple' would currently match 'apple')."""
    h = (host or "").lower()
    for name, tokens, _prio in brands:
        if any(t and t in h for t in tokens):
            return name
    return None


def lexical_family_root(host: str) -> str:
    """Coarse lexical family: TLD + a hyphen-density bucket. Groups
    paypal-a-b.tk with paypal-c-d.tk while separating paypal.xyz, without
    fragmenting per-domain. Richer families are a Track B refinement."""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    hyph = "h" if host.count("-") >= 3 else "l"
    return f"{tld}:{hyph}"


def cluster_key_for(brand: str, burst_day: str, family: str) -> str:
    return hashlib.sha1(f"{brand}|{burst_day}|{family}".encode()).hexdigest()


def _confidence(max_risk: float, count: int) -> float:
    """Strength (top member risk) tempered by corroboration (member count)."""
    return min(1.0, max_risk * (0.7 + 0.3 * min(count, 10) / 10.0))


def assemble(min_risk: float = 0.5) -> dict:
    with SessionLocal() as s:
        brands = load_brands(s)
        if not brands:
            return {"ok": False, "reason": "no active watchlist brands; run `make seed-brands`"}

        observations = s.execute(
            select(CtObservation).where(CtObservation.risk_score >= min_risk)
        ).scalars().all()

        # group candidate observations by stable cluster_key
        groups: dict[str, dict] = {}
        for o in observations:
            if o.event_ts is None:
                continue
            brand = target_brand_for(o.raw_host, brands)
            if not brand:
                continue
            burst_day = o.event_ts.astimezone(timezone.utc).date().isoformat()
            family = lexical_family_root(o.raw_host)
            key = cluster_key_for(brand, burst_day, family)
            g = groups.setdefault(key, {"brand": brand, "family": family,
                                        "burst_day": burst_day, "obs": []})
            g["obs"].append(o)

        created = merged = members_added = 0
        for key, g in groups.items():
            obs_list = g["obs"]
            event_ts_list = [o.event_ts for o in obs_list if o.event_ts]
            cluster = s.execute(
                select(CampaignCluster).where(CampaignCluster.cluster_key == key)
            ).scalar_one_or_none()

            if cluster is None:
                cluster = CampaignCluster(
                    cluster_key=key, target_brand=g["brand"], status="open", stage="new",
                    first_seen=min(event_ts_list), last_seen=max(event_ts_list),
                )
                s.add(cluster)
                s.flush()  # assign cluster.id
                created += 1
            else:
                merged += 1
                if event_ts_list:
                    cluster.first_seen = min(cluster.first_seen or min(event_ts_list), min(event_ts_list))
                    cluster.last_seen = max(cluster.last_seen or max(event_ts_list), max(event_ts_list))

            for o in obs_list:
                stmt = pg_insert(ClusterMember).values(
                    cluster_id=cluster.id,
                    observation_id=o.id,
                    membership_reason=f"brand={g['brand']} burst_day={g['burst_day']} family={g['family']}",
                    membership_score=float(o.risk_score or 0.0),
                ).on_conflict_do_nothing(constraint="uq_member_cluster_obs")
                members_added += s.execute(stmt).rowcount or 0

            # recompute aggregates from true membership (cumulative across runs)
            count = s.execute(
                select(func.count()).select_from(ClusterMember)
                .where(ClusterMember.cluster_id == cluster.id)
            ).scalar_one()
            max_risk = max((o.risk_score or 0.0 for o in obs_list), default=0.0)
            cluster.observation_count = count
            cluster.confidence_score = _confidence(float(max_risk), count)
            cluster.summary_reason = (
                f"{count} domain(s) impersonating {g['brand']} in a cert-issuance "
                f"burst on {g['burst_day']} (family {g['family']})"
            )

        s.commit()
        return {
            "ok": True,
            "candidate_obs": len(observations),
            "clusters_created": created,
            "clusters_merged": merged,
            "members_added": members_added,
        }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Assemble observations into campaign clusters.")
    ap.add_argument("--min-risk", type=float, default=float(os.getenv("OBS_MIN_RISK", "0.5")))
    args = ap.parse_args(argv)
    print(assemble(args.min_risk))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
