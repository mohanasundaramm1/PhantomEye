# product/stage_engine.py
"""Centralized campaign lifecycle (stage) transitions.

Four independent write-paths can each decide a cluster's stage should change:
ingest_observations.py (enrichment deepens), assemble_campaigns.py (cluster
created/merged), the disposition API endpoint (analyst judgment), and the
content probe (HTTP/MX evidence lands). This module is the ONLY place that
decides and applies stage changes -- no call site re-implements this logic.

Two functions, two very different contracts:

  evaluate_stage()        PURE. No I/O, no session, no locking. Given a
                          cluster's current state + its members + the latest
                          disposition + recent evidence, returns what the
                          stage SHOULD be right now. Fully unit-testable
                          without a database.

  apply_stage_transition() The ONLY transactional wrapper. Takes a row lock
                          on the cluster (SELECT ... FOR UPDATE), calls
                          evaluate_stage(), applies the idempotency guard,
                          writes an evidence_events row, commits. This is
                          what all four call sites actually call.

Why the lock: every other write path in product/ (assemble_campaigns.py,
ingest_observations.py) is lock-free by design, because it only ever APPENDS
(new cluster, new member row, ON CONFLICT DO NOTHING) -- idempotency alone is
sufficient, there is never a competing DECISION about the same field. Stage is
different: two writers (e.g. ingest advancing enrichment_level, and the probe
landing HTTP evidence, for the SAME cluster) can each independently and
correctly compute a DIFFERENT stage at the same instant. Under Postgres's
default READ COMMITTED isolation, two such UPDATEs are each individually
valid -- the last commit silently wins, with no error, no conflict. If the
"active" writer commits first and the "warming" writer (computed from a
stale read, before it saw the probe's evidence) commits second, the cluster
regresses from active back to warming. That is a real bug, not a cosmetic
duplicate-log-line annoyance, and idempotency guards alone do not prevent it
-- only a lock does. with_for_update() on the single campaign_clusters row
serializes exactly the four call sites that touch THIS cluster's stage,
without blocking unrelated clusters or blocking reads via GET /campaigns.

Idempotency guard is rank-based, not a linear scale:
    new(0) -> warming(1) -> active(2)   -- strictly forward-only, automatic
    {confirmed, suppressed}             -- TERMINAL, not ordered against each
                                           other; only a disposition or a
                                           suppression-rule match may enter
                                           them; automatic re-evaluation never
                                           touches a cluster already in either.

Manual override (a disposition) is tracked via stage_locked_by/stage_locked_at
on CampaignCluster (not a bool -- the UI needs "confirmed by analyst X on
<date>", and an audit trail needs to distinguish "auto-confirmed via MISP hit"
from "analyst confirmed it"). The automatic path checks the lock but NEVER
clears it; unlocking is only ever an explicit future action. While locked, the
automatic path still logs an INFORMATIONAL evidence_events row (applied=False)
so the trail isn't silent while a cluster is pinned.

Known, accepted limitation: evaluate_stage() takes the members of ONE cluster
and does not verify that none of those observations are ALSO a member of a
different cluster. cluster_key = sha1(brand|burst_day|lexical_family) is
stable for a given observation's (raw_host, event_ts) -- EXCEPT the brand
component, which target_brand_for() recomputes fresh against the live,
mutable watchlist_brands table on every assemble_campaigns.py run. If an
analyst edits brand priority/aliases between two runs, the same observation
could theoretically be attributed to a different brand and land in a second
cluster (ON CONFLICT DO NOTHING on cluster_members is keyed on the
(cluster_id, observation_id) PAIR, so a new pair for the same observation
under a different cluster is not a conflict at all). This is real but narrow
(requires a watchlist edit racing a reassembly) and orthogonal to stage
transitions -- not fixed here. Follow-up: either make brand attribution
sticky per-observation at first assembly, or add a merge-on-detection pass.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from product.models import CampaignCluster, ClusterMember, CtObservation, EvidenceEvent

# ---------- stage ranking ----------

_AUTO_STAGE_RANK = {"new": 0, "warming": 1, "active": 2}
TERMINAL_STAGES = {"confirmed", "suppressed"}
ALL_STAGES = set(_AUTO_STAGE_RANK) | TERMINAL_STAGES


def _utcnow():
    return datetime.now(timezone.utc)


# ---------- pure evaluation ----------

def evaluate_stage(
    cluster: CampaignCluster,
    members: list[CtObservation],
    disposition: dict | None,
    evidence: list[dict] | None = None,
) -> tuple[str, str]:
    """Pure function: given a cluster's current members + latest disposition
    + recent evidence, return the stage it SHOULD be at right now and why.

    Does NOT read the cluster's own current stage to decide the answer (the
    caller's idempotency guard handles "should we actually move" separately) --
    this only answers "what does the evidence support", so it's safe to call
    repeatedly and get the same answer for the same inputs.

    disposition: the latest analyst disposition dict for this cluster, or None.
      {"verdict": "confirmed" | "suppressed" | "benign", ...}
    evidence: recent evidence_events detail dicts for this cluster (optional;
      currently only used to detect suppression-rule matches and probe
      results that the caller didn't already fold into `members`).
    """
    evidence = evidence or []

    # An explicit analyst verdict is authoritative and short-circuits
    # everything else -- the disposition endpoint is the only other place
    # allowed to move a cluster into a terminal stage, and it calls this
    # function too so there's one source of truth for the mapping.
    if disposition is not None:
        verdict = disposition.get("verdict")
        if verdict == "confirmed":
            return "confirmed", "analyst disposition: confirmed"
        if verdict == "suppressed":
            return "suppressed", "analyst disposition: suppressed"
        if verdict == "benign":
            return "new", "analyst disposition: benign (reset to new)"

    # Automatic evidence checks, most-confirmed-first.
    if any(m.ti_misp_hit for m in members):
        return "confirmed", "external feed match (MISP) on a member domain"

    if any(e.get("event_type") == "suppression_match" for e in evidence):
        return "suppressed", "member domain matched an active suppression rule"

    # NOTE: mx_present is added to CtObservation in the Day 9 migration (the
    # content-probe schema prep); once it exists, a Day 10 follow-up adds a
    # check here (`any(m.mx_present for m in members)`). Not referenced yet
    # on purpose -- this function should only touch schema that exists today.
    if any(e.get("event_type") == "content_probe_result" and e.get("detail", {}).get("http_status")
           for e in evidence):
        return "active", "content probe returned live HTTP/MX evidence"

    if any((m.enrichment_level or "tier0") in ("tier1", "tier2") for m in members):
        return "warming", "DNS/registrar context landed on a member domain"

    return "new", "CT observation only, no enrichment context yet"


# ---------- transactional wrapper ----------

def apply_stage_transition(
    session: Session,
    cluster_id: int,
    *,
    disposition: dict | None = None,
    evidence: list[dict] | None = None,
    actor: str | None = None,
) -> dict:
    """The ONLY place stage is written. Locks the cluster row, evaluates,
    applies the idempotency guard, writes evidence_events, commits.

    Returns a dict describing what happened (for logging/tests):
      {"changed": bool, "old_stage": str, "new_stage": str, "reason": str,
       "locked": bool}
    """
    cluster = session.execute(
        select(CampaignCluster).where(CampaignCluster.id == cluster_id).with_for_update()
    ).scalar_one()

    members = session.execute(
        select(CtObservation)
        .join(ClusterMember, ClusterMember.observation_id == CtObservation.id)
        .where(ClusterMember.cluster_id == cluster_id)
    ).scalars().all()

    computed_stage, reason = evaluate_stage(cluster, members, disposition, evidence)
    old_stage = cluster.stage

    # A human lock is authoritative UNLESS this call is itself the disposition
    # that's setting/changing the lock (disposition is not None means the
    # disposition endpoint is calling us right now -- that's always allowed
    # to write, since it's the mechanism that sets the lock in the first place).
    if cluster.stage_locked_by is not None and disposition is None:
        session.add(EvidenceEvent(
            cluster_id=cluster_id,
            event_type="stage_evaluation_skipped_locked",
            observed_at=_utcnow(),
            detail={"computed_stage": computed_stage, "reason": reason, "applied": False,
                    "locked_by": cluster.stage_locked_by},
        ))
        session.commit()
        return {"changed": False, "old_stage": old_stage, "new_stage": old_stage,
                "reason": f"locked by {cluster.stage_locked_by}; would have computed {computed_stage}",
                "locked": True}

    if disposition is not None:
        # Disposition path: unconditional, always applies, always (re)locks.
        cluster.stage = computed_stage
        cluster.stage_locked_by = actor or "analyst"
        cluster.stage_locked_at = _utcnow()
        changed = old_stage != computed_stage
    else:
        # Automatic path: forward-only rank guard: terminal stages are never
        # touched here (only a disposition, handled above, or the MISP/
        # suppression checks inside evaluate_stage -- which ARE allowed to
        # enter a terminal stage automatically, e.g. a MISP hit landing after
        # the fact -- can reach a terminal stage via this path).
        if old_stage in TERMINAL_STAGES and computed_stage not in TERMINAL_STAGES:
            # Never let automatic re-evaluation walk a terminal stage backward.
            changed = False
        elif computed_stage in TERMINAL_STAGES:
            changed = old_stage != computed_stage
        else:
            changed = _AUTO_STAGE_RANK[computed_stage] > _AUTO_STAGE_RANK.get(old_stage, -1)
        if changed:
            cluster.stage = computed_stage

    if not changed:
        session.commit()  # release the lock even on a no-op
        return {"changed": False, "old_stage": old_stage, "new_stage": old_stage,
                "reason": reason, "locked": False}

    session.add(EvidenceEvent(
        cluster_id=cluster_id,
        event_type="stage_transition",
        observed_at=_utcnow(),
        detail={"from_stage": old_stage, "to_stage": cluster.stage, "reason": reason,
                "actor": actor if disposition is not None else "automatic"},
    ))
    session.commit()
    return {"changed": True, "old_stage": old_stage, "new_stage": cluster.stage,
            "reason": reason, "locked": disposition is not None}
