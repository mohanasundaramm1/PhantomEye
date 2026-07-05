# product/metrics.py
"""Analyst-facing operational metrics (Track D) -- SQL aggregates over the
now-complete table set (analyst_dispositions, campaign_clusters). Served via
GET /metrics/operations in api/main.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from product.db import SessionLocal
from product.models import AnalystDisposition, CampaignCluster


def _latest_disposition_ids(session):
    """Subquery: the most recent disposition id per cluster_id -- a cluster
    disposed more than once (e.g. suppressed, later reconsidered and
    confirmed) should count once, by its CURRENT verdict, not once per
    historical verdict change."""
    return (
        select(AnalystDisposition.cluster_id, func.max(AnalystDisposition.id).label("max_id"))
        .group_by(AnalystDisposition.cluster_id)
        .subquery()
    )


def analyst_confirmation_rate(session) -> dict:
    """Fraction of clusters an analyst has reviewed (their latest verdict)
    that were confirmed as real, vs. suppressed/benign."""
    sub = _latest_disposition_ids(session)
    verdicts = session.execute(
        select(AnalystDisposition.verdict).join(sub, AnalystDisposition.id == sub.c.max_id)
    ).scalars().all()
    total = len(verdicts)
    if total == 0:
        return {"rate": None, "n_dispositions": 0, "n_confirmed": 0}
    confirmed = sum(1 for v in verdicts if v == "confirmed")
    return {"rate": round(confirmed / total, 4), "n_dispositions": total, "n_confirmed": confirmed}


def median_time_to_first_review_hours(session) -> dict:
    """Median hours between a cluster's creation and its FIRST disposition --
    how fast analysts get to newly-formed campaigns. None if nothing has ever
    been reviewed (not zero, which would misleadingly read as "instant")."""
    first_review = (
        select(AnalystDisposition.cluster_id, func.min(AnalystDisposition.created_at).label("first_at"))
        .group_by(AnalystDisposition.cluster_id)
        .subquery()
    )
    rows = session.execute(
        select(CampaignCluster.created_at, first_review.c.first_at)
        .join(first_review, CampaignCluster.id == first_review.c.cluster_id)
    ).all()
    if not rows:
        return {"median_hours": None, "n": 0}
    hours = sorted(max(0.0, (first_at - created_at).total_seconds()) / 3600.0 for created_at, first_at in rows)
    n = len(hours)
    median = hours[n // 2] if n % 2 == 1 else (hours[n // 2 - 1] + hours[n // 2]) / 2.0
    return {"median_hours": round(median, 2), "n": n}


def suppression_rate(session) -> dict:
    """Fraction of ALL clusters (reviewed or not) currently at stage=suppressed
    -- a queue-noise health signal, distinct from confirmation rate (which
    only looks at reviewed clusters)."""
    total = session.execute(select(func.count()).select_from(CampaignCluster)).scalar_one()
    if total == 0:
        return {"rate": None, "n_total": 0, "n_suppressed": 0}
    suppressed = session.execute(
        select(func.count()).select_from(CampaignCluster).where(CampaignCluster.stage == "suppressed")
    ).scalar_one()
    return {"rate": round(suppressed / total, 4), "n_total": total, "n_suppressed": suppressed}


def campaigns_created_per_day(session, window_days: int = 7) -> dict:
    """Average new clusters/day over the last window_days (or since the
    earliest cluster, if there's less history than that)."""
    earliest = session.execute(select(func.min(CampaignCluster.created_at))).scalar_one()
    if earliest is None:
        return {"per_day": None, "window_days": window_days, "n_in_window": 0}
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    n_in_window = session.execute(
        select(func.count()).select_from(CampaignCluster).where(CampaignCluster.created_at >= cutoff)
    ).scalar_one()
    actual_days = max(1.0, min(float(window_days),
                               (datetime.now(timezone.utc) - earliest).total_seconds() / 86400.0))
    return {"per_day": round(n_in_window / actual_days, 2), "window_days": window_days, "n_in_window": n_in_window}


def enrichment_completeness_rate(session) -> dict:
    """Fraction of candidate ct_observations that reached full (tier2, WHOIS-
    backed) enrichment -- a pipeline-health signal, not an analyst one, but
    lands here since it's served by the same operations endpoint."""
    from product.models import CtObservation
    total = session.execute(select(func.count()).select_from(CtObservation)).scalar_one()
    if total == 0:
        return {"rate": None, "n_total": 0, "n_tier2": 0}
    tier2 = session.execute(
        select(func.count()).select_from(CtObservation).where(CtObservation.enrichment_level == "tier2")
    ).scalar_one()
    return {"rate": round(tier2 / total, 4), "n_total": total, "n_tier2": tier2}


def operations_summary() -> dict:
    with SessionLocal() as s:
        return {
            "analyst_confirmation": analyst_confirmation_rate(s),
            "median_time_to_first_review": median_time_to_first_review_hours(s),
            "suppression": suppression_rate(s),
            "campaigns_created": campaigns_created_per_day(s),
            "enrichment_completeness": enrichment_completeness_rate(s),
        }
