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

Suppression rules (product/suppression.py) are applied at candidate-selection
time: an observation matching an active, unexpired rule never joins a cluster
(new or existing) going forward. Separately, reevaluate_suppressed_clusters()
checks EXISTING clusters whose members have all come to match a rule (e.g. a
rule added after those domains already clustered) and pushes them to
stage="suppressed" via the stage engine -- candidate-time exclusion alone
would never touch an already-formed cluster again once none of its members
are still being freshly regrouped.

Weighted membership_score (Track B): refines per-member CONFIDENCE within an
already-formed cluster -- brand match + burst-window proximity + lexical
similarity to existing members + ASN/registrar overlap. cluster_key IDENTITY
is unchanged (still brand|burst_day|lexical_family); this only changes the
score attached to a member, not which cluster it joins, so the merge-never-
split guarantee is untouched.

Deferred to later tracks (documented, not silently missing):
    - SAN/nameserver overlap (would need a cert-level identifier the CT
      ingest pipeline doesn't currently capture -- see forwarder.py)
    - target_workflow intent extraction -> Track C

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

from ct.ingest.triage import _domain_under, levenshtein, load_config as load_triage_config
from product.db import SessionLocal
from product.models import (
    CampaignCluster,
    ClusterMember,
    CtObservation,
    WatchlistBrand,
)
from product.stage_engine import apply_stage_transition
from product.suppression import load_live_rules, matching_rule


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


def target_brand_for(host: str, brands, self_domains: dict | None = None) -> str | None:
    """Attribute a host to the highest-priority watchlist brand whose name/alias
    appears in it, EXCEPT when the host is that brand's own legitimate
    infrastructure (self_domains, reused from the triage provider-allowlist) --
    otherwise a brand's own high-scoring infra (e.g. graphql.fabric.microsoft.com)
    would form a fake "impersonation" campaign, exactly the Day-1 noise leaking
    back in via attribution. Substring match for the slice; token-boundary
    matching is a Track B refinement (so e.g. 'pineapple' would still match
    'apple')."""
    h = (host or "").lower()
    self_domains = self_domains or {}
    for name, tokens, _prio in brands:
        if any(t and t in h for t in tokens):
            own = self_domains.get(name)
            if own and _domain_under(h, own):
                continue  # the brand's OWN infra, not impersonation -- skip it
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


def _lexical_similarity(host: str, other_hosts: list[str]) -> float:
    """Average normalized similarity (1 - edit_distance/max_len) to other
    members' hostnames. 0.0 if there's nothing to compare against yet (a
    brand-new cluster's first member)."""
    others = [h for h in other_hosts if h]
    if not host or not others:
        return 0.0
    sims = [1.0 - (levenshtein(host, o) / max(len(host), len(o), 1)) for o in others]
    return sum(sims) / len(sims)


def _overlap_fraction(value: str | None, other_values: list) -> float:
    """Fraction of other_values sharing `value` (case-insensitive)."""
    others = [v for v in other_values if v]
    if not value or not others:
        return 0.0
    v = value.lower()
    return sum(1 for o in others if o.lower() == v) / len(others)


def _burst_proximity(event_ts, other_event_ts: list) -> float:
    """1.0 at the cluster's median event_ts, decaying linearly to 0.0 at 24h+
    away -- refines confidence WITHIN the existing calendar-day cluster_key
    grouping, does not change grouping itself. 0.5 (neutral) when there's
    nothing to compare against yet."""
    others = sorted(t for t in other_event_ts if t)
    if not others or event_ts is None:
        return 0.5
    median = others[len(others) // 2]
    hours_away = abs((event_ts - median).total_seconds()) / 3600.0
    return max(0.0, 1.0 - min(hours_away, 24.0) / 24.0)


def compute_membership_score(o: CtObservation, existing_members: list[CtObservation]) -> float:
    """Weighted signal blend (weights sum to 1.0): brand match (fixed, matching
    is a precondition to be a candidate at all) + burst-window proximity +
    lexical similarity to already-clustered members + ASN overlap + registrar
    overlap. This is a per-member CONFIDENCE refinement, not a clustering
    decision -- cluster_key alone still determines which cluster an
    observation joins."""
    burst = _burst_proximity(o.event_ts, [m.event_ts for m in existing_members])
    lexical = _lexical_similarity(o.raw_host or "", [m.raw_host for m in existing_members])
    asn = _overlap_fraction(o.sample_asn, [m.sample_asn for m in existing_members])
    registrar = _overlap_fraction(o.registrar, [m.registrar for m in existing_members])
    return round(0.30 + 0.25 * burst + 0.20 * lexical + 0.15 * asn + 0.10 * registrar, 4)


def reevaluate_suppressed_clusters(session, rules) -> int:
    """Existing clusters whose members have ALL come to match an active
    suppression rule get pushed to stage="suppressed" via the stage engine.
    Separate from the candidate-selection exclusion in assemble(): once a
    cluster's members stop being freshly regrouped (nothing new to add),
    candidate-time exclusion alone would never touch that cluster again, even
    though a rule added later should still suppress it. Returns the number of
    clusters transitioned."""
    if not rules:
        return 0
    cluster_ids = session.execute(select(CampaignCluster.id)).scalars().all()
    transitioned = 0
    for cid in cluster_ids:
        members = session.execute(
            select(CtObservation)
            .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
            .where(ClusterMember.cluster_id == cid)
        ).scalars().all()
        if members and all(matching_rule(m, rules) is not None for m in members):
            result = apply_stage_transition(
                session, cid,
                evidence=[{"event_type": "suppression_match",
                           "detail": {"matched_member_count": len(members)}}],
            )
            if result["changed"]:
                transitioned += 1
    return transitioned


def assemble(min_risk: float = 0.5) -> dict:
    with SessionLocal() as s:
        brands = load_brands(s)
        if not brands:
            return {"ok": False, "reason": "no active watchlist brands; run `make seed-brands`"}

        # reuse the triage provider-allowlist so a brand's own legit infra is
        # never attributed as impersonation (see target_brand_for).
        self_domains = load_triage_config().get("brand_self_domains", {})
        suppression_rules = load_live_rules(s)

        observations = s.execute(
            select(CtObservation).where(CtObservation.risk_score >= min_risk)
        ).scalars().all()

        # group candidate observations by stable cluster_key
        groups: dict[str, dict] = {}
        suppressed_candidates = 0
        for o in observations:
            if o.event_ts is None:
                continue
            if matching_rule(o, suppression_rules) is not None:
                suppressed_candidates += 1
                continue  # excluded from candidate grouping -- an active rule matched
            brand = target_brand_for(o.raw_host, brands, self_domains)
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

            # Baseline for weighted scoring is the cluster's PRE-EXISTING
            # members (empty for a brand-new cluster) -- deterministic and
            # order-independent, rather than scoring this batch against itself.
            existing_members = s.execute(
                select(CtObservation)
                .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
                .where(ClusterMember.cluster_id == cluster.id)
            ).scalars().all()

            for o in obs_list:
                stmt = pg_insert(ClusterMember).values(
                    cluster_id=cluster.id,
                    observation_id=o.id,
                    membership_reason=f"brand={g['brand']} burst_day={g['burst_day']} family={g['family']}",
                    membership_score=compute_membership_score(o, existing_members),
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

            # Call site 1/4 of the stage engine (product/stage_engine.py):
            # re-evaluate this cluster's stage now that its membership/aggregates
            # just changed (a newly-created cluster starts at "new"; a merge
            # might have just added a member whose enrichment/MISP status
            # justifies moving forward). Automatic path only -- no disposition,
            # so this can never touch a stage an analyst has locked, and can
            # only move forward (new->warming->active) or into a terminal
            # stage via real evidence (MISP hit), never backward.
            apply_stage_transition(s, cluster.id)

        suppressed = reevaluate_suppressed_clusters(s, suppression_rules)

        s.commit()  # no-op for cluster rows (each already committed via the
                    # stage-transition call above); harmless / keeps the
                    # session's own transaction boundary clean either way.
        return {
            "ok": True,
            "candidate_obs": len(observations),
            "suppressed_candidates": suppressed_candidates,
            "clusters_created": created,
            "clusters_merged": merged,
            "members_added": members_added,
            "clusters_newly_suppressed": suppressed,
        }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Assemble observations into campaign clusters.")
    ap.add_argument("--min-risk", type=float, default=float(os.getenv("OBS_MIN_RISK", "0.5")))
    args = ap.parse_args(argv)
    print(assemble(args.min_risk))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
