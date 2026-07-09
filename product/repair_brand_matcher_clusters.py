# product/repair_brand_matcher_clusters.py
"""One-time repair for campaign clusters formed by the pre-fix brand matcher.

Two bugs, fixed in sequence, both in the attribution path (ct/ingest/triage.py
brand_matches(), product/assemble_campaigns.py target_brand_for()/
classify_workflow()):
  1. A raw-substring fast-path (`kw in domain`) matched "apple" inside
     nzapplesandpears.com, rappleyplumbingandheating.com, etc. (fixed
     earlier, commit 8e92fb2).
  2. The token-boundary replacement still used a uniform Levenshtein
     distance<=2 budget regardless of keyword length -- "apps", "able",
     "maple" are all within distance 2 of "apple", so ordinary English
     words kept forming fake "apple impersonation" clusters. Fixed by
     _brand_match_distance_budget() (length-based budget, mostly exact-only
     for short names).

Live re-audit after fix #2 found 221 of 259 open clusters (215 fully-bogus,
6 partially-bogus) had members that no longer validly match their claimed
target_brand under the fixed matcher -- the matcher was that broken. This
script assesses (read-only) and repairs (only when explicitly asked to)
that damage.

Safety: never touches a cluster with stage_locked_by set (an analyst has
recorded a disposition on it) -- checked programmatically, not assumed.

Audit trail: for partial repairs (cluster survives, members pruned), a
data_correction EvidenceEvent is written on the cluster, mirroring the
existing pattern in product/stage_engine.py. For full deletions, an
EvidenceEvent is the WRONG instrument -- evidence_events.cluster_id has
ondelete="CASCADE", so a record attached to a cluster about to be deleted
would itself vanish with it, defeating the point. Full deletions are
logged instead to a structured JSONL file that survives the delete.

Run:
    python -m product.repair_brand_matcher_clusters --actor "your-name"           # assess only (default)
    python -m product.repair_brand_matcher_clusters --actor "your-name" --apply   # actually repair
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

from sqlalchemy import delete, select

from product.assemble_campaigns import _confidence, load_brands, target_brand_for
from product.db import SessionLocal
from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
DELETION_LOG_PATH = os.path.join(REPO_ROOT, "product", "logs", "brand_matcher_cluster_deletions.jsonl")


def _utcnow():
    return datetime.now(timezone.utc)


def _cluster_hosts(session, cluster_id: int) -> list[tuple[int, str, float, object]]:
    """(observation_id, raw_host, risk_score, event_ts) for every member."""
    rows = session.execute(
        select(CtObservation.id, CtObservation.raw_host, CtObservation.risk_score, CtObservation.event_ts)
        .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
        .where(ClusterMember.cluster_id == cluster_id)
    ).all()
    return [(r.id, r.raw_host, r.risk_score, r.event_ts) for r in rows]


def assess_corruption(session, brands=None, cluster_ids: list[int] | None = None) -> dict:
    """Read-only. Returns {cluster_id: {"target_brand", "total", "bad_observation_ids",
    "good_observation_ids"}} for every open cluster with at least one member
    that no longer matches its claimed target_brand under the current
    (fixed) matcher. Clusters where every member still matches are omitted
    entirely -- this dict IS the set of clusters needing repair.

    cluster_ids, if given, restricts the scan to exactly those clusters
    instead of every open cluster system-wide -- REQUIRED for tests that
    insert fixture clusters into the shared dev database rather than an
    isolated one: without this, a test's own repair() call would sweep up
    and mutate every other genuinely-corrupted cluster in the database as
    a side effect of just trying to test its own fixture. (Found live: a
    test run without this scoping actually deleted/pruned all real
    corrupted clusters as an unintended side effect -- the DATA outcome
    happened to already be correct and pre-verified via a separate dry
    run, but it happened via a test assertion, not a deliberate, reviewed
    --apply invocation, which is not how a destructive repair should ever
    run.)"""
    brands = brands if brands is not None else load_brands(session)
    query = select(CampaignCluster).where(CampaignCluster.status == "open")
    if cluster_ids is not None:
        query = query.where(CampaignCluster.id.in_(cluster_ids))
    open_clusters = session.execute(query).scalars().all()

    result = {}
    for c in open_clusters:
        if not c.target_brand:
            continue
        members = _cluster_hosts(session, c.id)
        if not members:
            continue
        bad, good = [], []
        for obs_id, host, _risk, _ts in members:
            if target_brand_for(host, brands) == c.target_brand:
                good.append(obs_id)
            else:
                bad.append(obs_id)
        if bad:
            result[c.id] = {
                "target_brand": c.target_brand,
                "total": len(members),
                "bad_observation_ids": bad,
                "good_observation_ids": good,
            }
    return result


def _append_deletion_log(entries: list[dict], path: str = DELETION_LOG_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        for entry in entries:
            f.write(json.dumps(entry, default=str) + "\n")


def repair(session, assessment: dict, actor: str, dry_run: bool = True,
          deletion_log_path: str = DELETION_LOG_PATH) -> dict:
    """Applies (or, if dry_run, just reports) the repair implied by
    assess_corruption()'s output. Returns a summary dict. Skips -- does not
    touch at all -- any cluster with stage_locked_by set."""
    summary = {
        "dry_run": dry_run, "actor": actor, "checked_utc": _utcnow().isoformat(),
        "deleted": [], "pruned": [], "skipped_locked": [],
    }
    deletion_log_entries = []

    for cluster_id, info in assessment.items():
        cluster = session.get(CampaignCluster, cluster_id)
        if cluster is None:
            continue  # already gone (e.g. re-running after a partial apply)
        if cluster.stage_locked_by is not None:
            summary["skipped_locked"].append({
                "cluster_id": cluster_id, "target_brand": info["target_brand"],
                "stage_locked_by": cluster.stage_locked_by,
            })
            continue

        fully_bogus = len(info["good_observation_ids"]) == 0

        if fully_bogus:
            entry = {
                "cluster_id": cluster_id, "cluster_key": cluster.cluster_key,
                "target_brand": info["target_brand"], "member_count": info["total"],
                "reason": "brand_matcher_false_positive_full", "actor": actor,
                "deleted_utc": _utcnow().isoformat(),
            }
            summary["deleted"].append(entry)
            if not dry_run:
                deletion_log_entries.append(entry)
                session.delete(cluster)  # cascades to cluster_members, evidence_events
        else:
            good_ids = info["good_observation_ids"]
            entry = {
                "cluster_id": cluster_id, "target_brand": info["target_brand"],
                "pruned_count": len(info["bad_observation_ids"]), "remaining_count": len(good_ids),
            }
            summary["pruned"].append(entry)
            if not dry_run:
                session.execute(
                    delete(ClusterMember).where(
                        ClusterMember.cluster_id == cluster_id,
                        ClusterMember.observation_id.in_(info["bad_observation_ids"]),
                    )
                )
                remaining = session.execute(
                    select(CtObservation.risk_score, CtObservation.event_ts)
                    .where(CtObservation.id.in_(good_ids))
                ).all()
                max_risk = max((r.risk_score for r in remaining if r.risk_score is not None), default=0.0)
                cluster.confidence_score = _confidence(float(max_risk), len(remaining))
                cluster.observation_count = len(remaining)
                event_times = [r.event_ts for r in remaining if r.event_ts is not None]
                if event_times:
                    cluster.first_seen = min(event_times)
                    cluster.last_seen = max(event_times)
                session.add(EvidenceEvent(
                    cluster_id=cluster_id,
                    event_type="data_correction",
                    observed_at=_utcnow(),
                    detail={
                        "action": "members_pruned", "reason": "brand_matcher_false_positive_partial",
                        "pruned_count": len(info["bad_observation_ids"]),
                        "new_confidence": cluster.confidence_score,
                        "new_observation_count": cluster.observation_count,
                        "actor": actor,
                    },
                ))

        if not dry_run:
            session.commit()

    if not dry_run and deletion_log_entries:
        _append_deletion_log(deletion_log_entries, path=deletion_log_path)

    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--actor", required=True, help="Who/what is running this repair (for the audit trail).")
    ap.add_argument("--apply", action="store_true", help="Actually perform the repair. Without this, assess-only.")
    args = ap.parse_args(argv)

    with SessionLocal() as session:
        assessment = assess_corruption(session)
        print(f"[info] {len(assessment)} open clusters need repair "
              f"({sum(1 for v in assessment.values() if not v['good_observation_ids'])} fully-bogus, "
              f"{sum(1 for v in assessment.values() if v['good_observation_ids'])} partially-bogus)")

        summary = repair(session, assessment, actor=args.actor, dry_run=not args.apply)

    print(f"[info] dry_run={summary['dry_run']}")
    print(f"[info] would delete / deleted: {len(summary['deleted'])}")
    print(f"[info] would prune / pruned:   {len(summary['pruned'])}")
    print(f"[info] skipped (locked):       {len(summary['skipped_locked'])}")
    if summary["skipped_locked"]:
        print("[warn] locked clusters skipped:", summary["skipped_locked"])
    if not args.apply:
        print("[info] dry run only -- re-run with --apply to actually repair.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
