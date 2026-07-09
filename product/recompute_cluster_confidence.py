# product/recompute_cluster_confidence.py
"""Recompute every open CampaignCluster's confidence_score from its
members' CURRENT risk_score -- needed after anything that changes stored
risk_scores out from under already-formed clusters (e.g.
ct/score/rescore_ct_observations.py), since confidence_score is a
derived/cached value (product/assemble_campaigns.py::_confidence()), not
recomputed live on every read.

Must run after both:
  1. product/repair_brand_matcher_clusters.py (corrected membership --
     otherwise this would compute confidence off members that don't
     belong in the cluster).
  2. ct/score/rescore_ct_observations.py (corrected risk_scores).
Running it before either just means it'll need to run again after --
recomputation is idempotent given the same inputs, not harmful to re-run.

Run:
    python -m product.recompute_cluster_confidence               # dry run, reports deltas
    python -m product.recompute_cluster_confidence --apply        # writes confidence_score
"""
from __future__ import annotations

import argparse

from sqlalchemy import select

from product.assemble_campaigns import _confidence
from product.db import SessionLocal
from product.models import CampaignCluster, ClusterMember, CtObservation


def compute_deltas(session, cluster_ids: list[int] | None = None) -> list[dict]:
    """Read-only. One row per open cluster whose stored confidence_score no
    longer matches what _confidence() would compute from its members'
    current risk_score.

    cluster_ids, if given, restricts the scan to exactly those clusters --
    same rationale as product/repair_brand_matcher_clusters.py's
    assess_corruption(): required for tests inserting fixture clusters
    into the shared dev database, so a caller can't accidentally pass an
    unscoped, system-wide result straight to apply_deltas()."""
    query = select(CampaignCluster).where(CampaignCluster.status == "open")
    if cluster_ids is not None:
        query = query.where(CampaignCluster.id.in_(cluster_ids))
    clusters = session.execute(query).scalars().all()
    deltas = []
    for c in clusters:
        members = session.execute(
            select(CtObservation.risk_score)
            .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
            .where(ClusterMember.cluster_id == c.id)
        ).scalars().all()
        if not members:
            continue
        max_risk = max((m for m in members if m is not None), default=0.0)
        new_confidence = _confidence(float(max_risk), len(members))
        if abs(new_confidence - (c.confidence_score or 0.0)) > 1e-6:
            deltas.append({
                "cluster_id": c.id, "target_brand": c.target_brand,
                "old_confidence": c.confidence_score, "new_confidence": new_confidence,
                "member_count": len(members),
            })
    return deltas


def apply_deltas(session, deltas: list[dict]) -> int:
    n = 0
    for d in deltas:
        cluster = session.get(CampaignCluster, d["cluster_id"])
        if cluster is None:
            continue
        cluster.confidence_score = d["new_confidence"]
        n += 1
    session.commit()
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Actually write new confidence_score. Without this, dry-run only.")
    args = ap.parse_args(argv)

    with SessionLocal() as session:
        deltas = compute_deltas(session)
        print(f"[info] {len(deltas)} open clusters need a confidence_score update")
        if deltas:
            avg_delta = sum(abs(d["new_confidence"] - (d["old_confidence"] or 0.0)) for d in deltas) / len(deltas)
            print(f"[info] mean |delta|={avg_delta:.4f}")

        if args.apply:
            n = apply_deltas(session, deltas)
            print(f"[info] applied: updated {n} clusters.")
        else:
            print("[info] dry run only -- re-run with --apply to write the new confidence scores.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
